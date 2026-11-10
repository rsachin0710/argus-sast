"""Agent implementations.

    Recon       1 call per scan     -> RepoContext (frameworks, entry points, auth, protections)
    Hunter      chunks x groups x votes -> raw candidate findings
    Tracer      <= tool_budget+1 calls per candidate -> source -> sink data flow
    Verifier    1 call per candidate -> confirmed | needs_context | rejected (+ severity factors)
    Remediator  1 call per confirmed / needs-context finding -> replacement code

Agents never touch the file system directly: the Tracer reads code only
through the read-only, redacted ``CodeIndex`` tools, and nothing here can
write files. Every call goes through ``LLMClient`` (cache, retries, budget,
schema validation).
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

from ..config import Language, Settings
from ..findings import FlowStep
from ..index import Chunk, CodeIndex
from ..llm.client import LLMClient
from ..rules.engine import Signal
from ..rules.model import Rule
from ..security import fence_code
from ..taxonomy import FOCUS_CWES, OWASP_2025_NAMES, cwe_label, parse_cwe
from . import prompts as P
from .schemas import (
    HunterFinding,
    HunterOutput,
    ReconOutput,
    RemediatorOutput,
    TracerAction,
    VerifierOutput,
)

# Keywords in build files / imports -> framework names (deterministic recon).
_FRAMEWORK_HINTS = [
    ("spring-boot", "Spring Boot"),
    ("spring-security", "Spring Security"),
    ("org.springframework", "Spring"),
    ("jakarta.servlet", "Jakarta Servlet"),
    ("javax.servlet", "Java Servlet"),
    ("struts", "Apache Struts"),
    ("hibernate", "Hibernate"),
    ("jdbc", "JDBC"),
    ("django", "Django"),
    ("flask", "Flask"),
    ("fastapi", "FastAPI"),
    ("sqlalchemy", "SQLAlchemy"),
    ("jinja2", "Jinja2"),
    ('"express"', "Express"),
    ("require('express')", "Express"),
    ('require("express")', "Express"),
    ('"koa"', "Koa"),
    ("@nestjs", "NestJS"),
    ('"next"', "Next.js"),
    ('"react"', "React"),
    ('"mongoose"', "Mongoose / MongoDB"),
    ('"sequelize"', "Sequelize"),
    ('"pg"', "PostgreSQL (pg)"),
    ('"helmet"', "helmet"),
    ('"csurf"', "csurf"),
    ("passport", "Passport"),
    ("jsonwebtoken", "jsonwebtoken (JWT)"),
]
_BUILD_FILES = ["pom.xml", "build.gradle", "build.gradle.kts", "requirements.txt", "pyproject.toml",
                "setup.py", "Pipfile", "package.json", "settings.py", "application.properties",
                "application.yml", "application.yaml"]
_ROUTE_RE = re.compile(
    r"@(Get|Post|Put|Delete|Patch|Request)Mapping|@(RestController|Controller|PreAuthorize|Secured|RolesAllowed)"
    r"|@(app|router|bp|blueprint|api)\.(route|get|post|put|delete|patch)"
    r"|\b(app|router)\.(get|post|put|delete|patch|use|all)\s*\("
    r"|\bpath\(|\burlpatterns\b|login_required|permission_classes|MIDDLEWARE|SecurityFilterChain|csrf|cors|helmet"
)


@dataclass
class RepoContext:
    frameworks: list[str] = field(default_factory=list)
    entry_points: list[str] = field(default_factory=list)
    auth_model: str = ""
    global_protections: list[str] = field(default_factory=list)
    data_stores: list[str] = field(default_factory=list)
    notes: str = ""
    user_notes: str = ""  # developer-supplied context (argus context note ...)

    def render(self) -> str:
        lines = ["Repository context (from the Recon agent; may be incomplete):"]
        if self.frameworks:
            lines.append(f"- Frameworks: {', '.join(self.frameworks)}")
        if self.entry_points:
            lines.append(f"- Entry points: {'; '.join(self.entry_points[:10])}")
        if self.auth_model:
            lines.append(f"- Authentication / authorization: {self.auth_model}")
        if self.global_protections:
            lines.append(f"- Global protections: {'; '.join(self.global_protections)}")
        if self.data_stores:
            lines.append(f"- Data stores: {', '.join(self.data_stores)}")
        if self.notes:
            lines.append(f"- Notes: {self.notes}")
        if self.user_notes:
            lines.append(f"Context provided by the developer (trusted): {self.user_notes}")
        return "\n".join(lines) + "\n"

    def as_dict(self) -> dict:
        return dict(self.__dict__)

    @classmethod
    def from_dict(cls, d: dict) -> "RepoContext":
        return cls(**{k: v for k, v in (d or {}).items() if k in cls.__dataclass_fields__})


@dataclass
class TraceResult:
    data_flow: list[FlowStep]
    summary: str
    sanitized: bool


def detect_frameworks(root: Path | None, index: CodeIndex) -> list[str]:
    """Cheap, deterministic framework detection from build files and imports."""
    blobs: list[str] = []
    if root is not None:
        for name in _BUILD_FILES:
            p = root / name
            if p.is_file() and p.stat().st_size < 500_000:
                blobs.append(p.read_text("utf-8", "replace").lower())
    for fi in index.files.values():
        blobs.append("\n".join(fi.lines[:60]).lower())
    text = "\n".join(blobs)
    found: list[str] = []
    for needle, name in _FRAMEWORK_HINTS:
        if needle.lower() in text and name not in found:
            found.append(name)
    return found


class Agents:
    def __init__(self, llm: LLMClient, settings: Settings, index: CodeIndex | None = None):
        self.llm = llm
        self.settings = settings
        self.index = index

    # ------------------------------------------------------------------ Recon
    async def recon(self, root: Path | None, detected: list[str]) -> RepoContext:
        assert self.index is not None
        files = sorted(self.index.files)
        langs = sorted({fi.source.language.value for fi in self.index.files.values()})
        excerpts = []
        if root is not None:
            for name in _BUILD_FILES:
                p = root / name
                if p.is_file() and p.stat().st_size < 500_000:
                    body = p.read_text("utf-8", "replace")[:1500]
                    excerpts.append(f"--- {name} ---\n{body}")
        route_lines = []
        for rel in files:
            for i, line in enumerate(self.index.files[rel].redacted):
                if len(line) < 400 and _ROUTE_RE.search(line):
                    route_lines.append(f"{rel}:{i + 1}: {line.strip()[:160]}")
                    if len(route_lines) >= 60:
                        break
            if len(route_lines) >= 60:
                break
        user = P.RECON_USER.format(
            languages=", ".join(langs),
            detected=", ".join(detected) or "nothing conclusive",
            file_count=len(files),
            shown=min(80, len(files)),
            file_list="\n".join(files[:80]),
            build_excerpts=fence_code("build-files", "\n\n".join(excerpts).splitlines() or ["(none)"], 1),
            route_lines=fence_code("route-lines", route_lines or ["(none found)"], 1),
        )
        out = await self.llm.structured(system=P.system(P.RECON_ROLE), user=user, model_cls=ReconOutput)
        frameworks = list(dict.fromkeys([*detected, *out.frameworks]))
        return RepoContext(
            frameworks=frameworks,
            entry_points=out.entry_points,
            auth_model=out.auth_model,
            global_protections=out.global_protections,
            data_stores=out.data_stores,
            notes=out.notes,
        )

    # ----------------------------------------------------------------- Hunter
    def _checklist(self, categories: list[str]) -> str:
        parts = []
        for cat in categories:
            items = FOCUS_CWES.get(cat, [])
            if not items:
                continue
            parts.append(f"{cat}:2025 {OWASP_2025_NAMES[cat]}")
            parts.extend(f"  - CWE-{cwe}: {hint}" for cwe, hint in items)
        return "\n".join(parts)

    @staticmethod
    def _custom_checks(ai_rules: list[Rule], language: Language) -> str:
        applicable = [r for r in ai_rules if language in r.languages]
        if not applicable:
            return ""
        lines = ["Organisation-specific checks (custom rules; report violations with the rule's CWE and set related_rule):"]
        for r in applicable:
            lines.append(f"  - [{r.id}] {r.cwe}: {r.instruction.strip()}")
        return "\n".join(lines) + "\n"

    async def hunt(
        self,
        chunk: Chunk,
        categories: list[str],
        signals: list[Signal],
        ai_rules: list[Rule],
        repo_ctx: RepoContext,
        vote: int,
    ) -> list[HunterFinding]:
        assert self.index is not None
        fi = self.index.files[chunk.file]
        code_parts = []
        header_note = ""
        if chunk.header_end:
            header_note = f" Lines 1-{chunk.header_end} (imports) are included as context."
            code_parts.append(fence_code(chunk.file, fi.redacted[: chunk.header_end], 1))
        code_parts.append(fence_code(chunk.file, fi.redacted[chunk.start_line - 1 : chunk.end_line], chunk.start_line))
        in_range = [s for s in signals if chunk.start_line <= s.line <= chunk.end_line][:40]
        user = P.HUNTER_USER.format(
            repo_context=repo_ctx.render(),
            path=chunk.file,
            language=chunk.language.value,
            start=chunk.start_line,
            end=chunk.end_line,
            header_note=header_note,
            checklist=self._checklist(categories),
            custom_checks=self._custom_checks(ai_rules, chunk.language),
            signals="\n".join(s.hint_line() for s in in_range) or "(none)",
            code="\n\n".join(code_parts),
        )
        out = await self.llm.structured(
            system=P.system(P.HUNTER_ROLE), user=user, model_cls=HunterOutput, vote=vote
        )
        return out.findings

    # ----------------------------------------------------------------- Tracer
    def _run_tool(self, action: str, args: dict) -> str:
        assert self.index is not None
        try:
            if action == "read_lines":
                return self.index.read_lines(str(args.get("path", "")), int(args.get("start", 1)), int(args.get("end", 40)))
            if action == "get_symbol":
                return self.index.get_symbol(str(args.get("name", "")))
            if action == "find_callers":
                return self.index.find_callers(str(args.get("name", "")))
            if action == "search":
                return self.index.search(str(args.get("pattern", "")))
        except (ValueError, TypeError) as exc:
            return f"ERROR: bad arguments: {exc}"
        return f"ERROR: unknown tool {action!r}"

    async def trace(self, path: str, line: int, title: str, cwe: str, reason: str) -> TraceResult:
        assert self.index is not None
        fi = self.index.files[path]
        start, end = fi.window_for(line, max_lines=80)
        budget = self.settings.scan.tool_budget
        user = P.TRACER_USER.format(
            title=title, cwe=cwe, path=path, line=line, reason=reason[:1500],
            code=fence_code(path, fi.redacted[start - 1 : end], start), budget=budget,
        )
        history: list[dict] = []
        action: TracerAction | None = None
        for step in range(budget + 1):
            msg = user if step < budget else user + "\n\n" + P.TRACER_FORCE_FINAL
            action = await self.llm.structured(
                system=P.system(P.TRACER_ROLE), user=msg, model_cls=TracerAction, history=history
            )
            # Typed args have a fixed field order, so a cached answer and a fresh
            # one produce byte-identical follow-up prompts (keeps the cache hitting).
            args = action.args.used()
            if action.action == "final" or step == budget:
                break
            result = self._run_tool(action.action, args)[:6000]
            history += [
                {"role": "user", "content": msg},
                {"role": "assistant", "content": action.model_dump_json(exclude_none=True)},
            ]
            user = P.TRACER_TOOL_RESULT.format(
                action=action.action,
                args=json.dumps(args, sort_keys=True)[:300],
                result=fence_code("tool-result", result.splitlines() or ["(empty)"], 1),
                remaining=budget - step - 1,
            )
        flow: list[FlowStep] = []
        if action is not None and action.action == "final":
            for st in action.data_flow[:15]:
                f = self.index.files.get(st.file)
                if f is None or not (1 <= st.line <= len(f.lines)):
                    continue  # drop steps that point at lines that do not exist
                flow.append(FlowStep(file=st.file, line=st.line, role=st.role, note=st.note[:300]))
            return TraceResult(flow, action.summary[:2000], action.sanitized)
        return TraceResult([], "", False)

    # --------------------------------------------------------------- Verifier
    async def verify(
        self,
        *,
        title: str,
        cwe: str,
        cwe_name: str,
        path: str,
        line: int,
        function: str | None,
        detector: str,
        reason: str,
        rule: Rule | None,
        trace: TraceResult | None,
        window_start: int,
        window_lines: list[str],
        repo_ctx: RepoContext,
        user_answer: str | None,
    ) -> VerifierOutput:
        rule_info = ""
        if rule is not None:
            rule_info = f"- Matched rule {rule.id}: {rule.message}\n"
        flow = ""
        if trace is not None and (trace.data_flow or trace.summary):
            steps = "\n".join(f"    {s.role}: {s.file}:{s.line} {s.note}" for s in trace.data_flow)
            flow = (
                f"- Data flow from the Tracer agent{' (Tracer believes the path is sanitised)' if trace.sanitized else ''}:\n"
                f"{steps}\n    Summary: {trace.summary}\n"
            )
        user_context = ""
        if user_answer:
            user_context = f"- The developer answered a previous question about this finding (trusted): {user_answer}\n"
        user = P.VERIFIER_USER.format(
            repo_context=repo_ctx.render(),
            title=title,
            cwe=cwe,
            cwe_name=cwe_name,
            path=path,
            line=line,
            function=function or "module level",
            detector=detector,
            reason=reason[:2000] or "(rule match)",
            rule_info=rule_info,
            flow=flow,
            user_context=user_context,
            code=fence_code(path, window_lines, window_start),
        )
        out = await self.llm.structured(system=P.system(P.VERIFIER_ROLE), user=user, model_cls=VerifierOutput)
        if parse_cwe(out.cwe) is None:
            out.cwe = cwe
        else:
            out.cwe = cwe_label(parse_cwe(out.cwe))
        if out.verdict == "needs_context" and not (out.context_question or "").strip():
            out.context_question = "What additional context determines whether this input is attacker-controlled?"
        return out

    # ------------------------------------------------------------- Remediator
    async def remediate(
        self,
        *,
        title: str,
        cwe: str,
        path: str,
        line: int,
        language: str,
        explanation: str,
        rule: Rule | None,
        window_start: int,
        window_lines: list[str],
    ) -> RemediatorOutput:
        rule_hint = f"Suggested approach: {rule.remediation}\n" if rule is not None and rule.remediation else ""
        user = P.REMEDIATOR_USER.format(
            title=title,
            cwe=cwe,
            path=path,
            line=line,
            explanation=explanation[:2500],
            rule_hint=rule_hint,
            language=language,
            win_start=window_start,
            win_end=window_start + len(window_lines) - 1,
            code=fence_code(path, window_lines, window_start),
        )
        return await self.llm.structured(system=P.system(P.REMEDIATOR_ROLE), user=user, model_cls=RemediatorOutput)
