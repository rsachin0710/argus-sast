"""ScanService: the one scan engine behind the CLI, the web UI and CI.

End-to-end flow of ``ScanService.run_async`` (each step is commented below):

    1. settings     defaults -> user config -> safe project keys -> env -> overrides
    2. target       file / folder / GitHub repo / PR  -> read-only SourceFiles
    3. rules        built-in + user + --rules + (optional) project rules
    4. index        tree-sitter functions, chunks, secret redaction
    5. signals      deterministic rule matches + inline suppressions + baseline
    6. recon        (AI) repository context: frameworks, entry points, auth
    7. hunt         (AI) chunks x hunter groups x votes -> line-verified candidates
    8. merge        AI candidates + `report` rule matches, de-duplicated
    9. per finding  (AI) Tracer -> Verifier -> Remediator
                    (rules-only mode: rule matches are reported as "unverified")
   10. finalise     fingerprints, IDs, filters, sorting, stats
   11. persist      run.json, findings.json, report.txt, SARIF/MD, patches

The scanned code is only ever READ. Fixes are applied separately, with
explicit consent, by ``argus.fixer``.
"""

from __future__ import annotations

import asyncio
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from . import PROMPT_VERSION
from .agents.agents import Agents, RepoContext, TraceResult, detect_frameworks
from .config import SEVERITY_ORDER, Language, Settings, load_settings, project_overrides
from .findings import (
    CodeContext,
    Finding,
    Remediation,
    ScanRun,
    SeverityFactors,
    compute_severity,
    finding_id,
    fingerprint,
    same_issue,
    severity_rank,
    utcnow,
    verify_location,
    vote_merge,
)
from .index import CodeIndex, FileIndex
from .llm import BudgetExceeded, LLMClient, LLMError, ResponseCache, create_provider
from .config import data_dir
from .remediation import build_patch, remediation_from
from .reports import write_reports
from .rules import RuleEngine, RuleSet, Signal, is_suppressed, load_rules, suppressions
from .rules.model import Rule, RuleMode, RuleType
from .store import ContextStore, RunStore, load_baseline
from .targets import Target, TargetError, resolve_target
from .taxonomy import (
    HUNTER_GROUPS,
    categories_to_2025,
    cwe_label,
    cwe_name,
    is_known_cwe,
    mitre_url,
    owasp_for,
    parse_cwe,
)

ProgressFn = Callable[[str, dict], None]


class ScanCancelled(Exception):
    pass


@dataclass
class ScanOptions:
    target: str | None = None
    ref: str | None = None
    github_pr: str | None = None
    since: str | None = None
    ai: bool = True  # False = rules-only (no LLM calls at all)
    rule_paths: list[str] = field(default_factory=list)
    overrides: dict = field(default_factory=dict)  # nested settings overrides
    baseline: str | None = None
    run_id: str | None = None
    out_dir: str | None = None  # also copy reports here (CLI default: ./argus-results)
    llm_client: LLMClient | None = None  # injected in tests


@dataclass
class _Candidate:
    """A possible finding before the Verifier has ruled on it."""

    file: str
    line: int
    end_line: int
    cwe: str
    title: str
    reason: str
    source: str | None
    detector: str  # ai | rule | ai+rule
    rule: Rule | None = None
    votes: int = 1
    vote_total: int = 1


class ScanService:
    def __init__(self, store: RunStore | None = None):
        self.store = store or RunStore()

    # ------------------------------------------------------------------ API
    def run(self, opts: ScanOptions, progress: ProgressFn | None = None,
            cancel: threading.Event | None = None) -> ScanRun:
        """Synchronous wrapper used by the CLI and the web worker thread."""
        return asyncio.run(self.run_async(opts, progress, cancel))

    async def run_async(self, opts: ScanOptions, progress: ProgressFn | None = None,
                        cancel: threading.Event | None = None) -> ScanRun:
        started = time.monotonic()
        emit = progress or (lambda event, data: None)
        run = ScanRun(id=opts.run_id or self.store.new_run_id(), target=opts.target or opts.github_pr or "")
        run.status = "running"
        target: Target | None = None
        llm: LLMClient | None = None

        def phase(name: str, frac: float, **data) -> None:
            if cancel is not None and cancel.is_set():
                raise ScanCancelled()
            run.phase, run.progress = name, round(frac, 3)
            emit("phase", {"phase": name, "progress": run.progress, **data})

        try:
            # 1-2. Settings and target ------------------------------------------
            phase("resolving target", 0.02)
            settings = load_settings(opts.overrides)
            target = resolve_target(opts.target, settings, ref=opts.ref, github_pr=opts.github_pr, since=opts.since)
            settings = load_settings(opts.overrides, target_root=target.root)  # + safe project keys
            self._apply_project_scope(target, settings)
            run.target_kind = target.kind
            if target.kind in ("file", "directory"):
                run.target = str(Path(opts.target).expanduser().resolve())
            run.target_root = None if target.is_temporary else str(target.root)
            run.target_key = target.key
            run.repo_url, run.ref = target.repo_url, target.ref
            run.ai_enabled = opts.ai
            run.provider = settings.llm.provider.value if opts.ai else None
            run.model = settings.llm.model if opts.ai else None
            run.owasp_edition = settings.scan.owasp_edition
            run.settings = settings.model_dump(mode="json")
            run.skipped_files = target.skipped
            run.file_hashes = {f.rel_path: f.sha256 for f in target.files}
            run.stats.files_scanned = len(target.files)
            run.stats.files_skipped = len(target.skipped)
            run.stats.lines_scanned = sum(len(f.lines) for f in target.files)
            self.store.save(run)
            if not target.files:
                run.warnings.append("No Java, Python or JavaScript files found to scan.")

            # 3. Rules --------------------------------------------------------
            phase("loading rules", 0.05)
            ruleset = load_rules(settings, opts.rule_paths, target.root)
            run.stats.rules_loaded = len([r for r in ruleset.rules.values() if r.enabled])
            run.custom_rule_ids = sorted(r.id for r in ruleset.rules.values() if r.origin != "builtin" and r.enabled)
            run.stats.custom_rules = len(run.custom_rule_ids)
            run.warnings.extend(f"rule error: {e}" for e in ruleset.errors)

            # 4. Index ----------------------------------------------------------
            phase("indexing code", 0.07, files=len(target.files))
            index = CodeIndex(target.files, redact=settings.scan.redact_secrets)
            run.stats.secrets_redacted = sum(fi.redactions for fi in index.files.values())

            # 5. Signals, suppressions, context, baseline -------------------------
            engine = RuleEngine(ruleset)
            signals: dict[str, list[Signal]] = {}
            supp: dict[str, dict[int, set[str]]] = {}
            for rel, fi in index.files.items():
                signals[rel] = engine.scan_file(rel, fi.source.language, fi.lines)
                supp[rel] = suppressions(fi.lines)
            run.stats.signals = sum(len(v) for v in signals.values())
            ctx_store = ContextStore(target.key)
            _, proj_ctx = project_overrides(target.root)
            user_notes = "\n".join(x for x in [ctx_store.notes, str(proj_ctx.get("notes", ""))] if x).strip()
            baseline_path = Path(opts.baseline) if opts.baseline else target.root / ".argus-baseline.json"
            baseline = load_baseline(baseline_path)

            categories = categories_to_2025(settings.scan.categories, settings.scan.owasp_edition)
            candidates: list[_Candidate] = []
            repo_ctx = RepoContext(frameworks=detect_frameworks(target.root, index), user_notes=user_notes)
            agents: Agents | None = None

            if opts.ai and target.files:
                llm = opts.llm_client or self._make_llm(settings)
                agents = Agents(llm, settings, index)

                # 6. Recon --------------------------------------------------------
                phase("recon agent", 0.1)
                try:
                    repo_ctx = await agents.recon(target.root, repo_ctx.frameworks)
                    repo_ctx.user_notes = user_notes
                except (LLMError, BudgetExceeded) as exc:
                    run.warnings.append(f"recon agent failed, continuing without it: {exc}")
                run.repo_context = repo_ctx.as_dict()

                # 7. Hunt -------------------------------------------------------
                candidates = await self._hunt(run, settings, index, signals, ruleset, repo_ctx, agents,
                                              categories, phase)

            # 8. Merge `report` rule matches with AI candidates --------------------
            phase("merging rule matches", 0.62)
            candidates = self._merge_rule_signals(candidates, signals, ruleset)

            # Build Finding objects (fingerprints, code windows) and apply
            # suppressions BEFORE spending LLM calls on verification.
            findings: list[tuple[Finding, _Candidate]] = []
            for cand in candidates:
                f = self._to_finding(cand, index.files[cand.file])
                if is_suppressed(supp[cand.file], cand.line, cand.cwe, cand.rule.id if cand.rule else None):
                    f.status, f.suppressed_reason = "suppressed", "inline argus-ignore comment"
                elif f.fingerprint in baseline:
                    f.status, f.suppressed_reason = "suppressed", f"in baseline {baseline_path.name}"
                f.context_answer = ctx_store.answer_for(f.fingerprint)
                findings.append((f, cand))

            # 9. Trace -> verify -> remediate --------------------------------------
            if agents is not None:
                await self._verify_all(run, settings, index, findings, repo_ctx, agents, phase)
            else:
                self._rules_only(findings)

            # 10. Finalise ------------------------------------------------------
            phase("finalising", 0.96)
            final = self._finalise(run, settings, findings, categories)
            run.findings = final
            run.signals_not_flagged = self._unflagged(signals, final) if opts.ai else []
            if llm is not None:
                st = llm.stats
                run.stats.llm_calls, run.stats.llm_cache_hits = st.calls, st.cache_hits
                run.stats.llm_failures = st.failures
                run.stats.input_tokens, run.stats.output_tokens = st.input_tokens, st.output_tokens
            run.status = "completed"
        except ScanCancelled:
            run.status = "cancelled"
            run.errors.append("scan cancelled by user")
        except TargetError as exc:
            run.status = "failed"
            run.errors.append(str(exc))
        except Exception as exc:  # keep the run record even on bugs
            run.status = "failed"
            run.errors.append(f"{type(exc).__name__}: {exc}")
        finally:
            if llm is not None and opts.llm_client is None:
                await llm.aclose()
            if target is not None:
                target.cleanup()  # delete temporary clones
            run.stats.duration_seconds = round(time.monotonic() - started, 2)
            run.finished_at = utcnow()
            run.phase, run.progress = ("done", 1.0) if run.status == "completed" else (run.status, run.progress)
            self.store.save(run)
            # 11. Reports: JSON + TXT always, SARIF / MD when configured.
            try:
                formats = run.settings.get("output", {}).get("formats") or ["json", "txt"]
                write_reports(run, self.store.run_dir(run.id), formats,
                              Path(opts.out_dir) if opts.out_dir else None)
            except OSError as exc:
                run.errors.append(f"could not write reports: {exc}")
                self.store.save(run)
            emit("done", {"status": run.status, "run_id": run.id})
        return run

    # -------------------------------------------------------------- helpers
    @staticmethod
    def _make_llm(settings: Settings) -> LLMClient:
        provider = create_provider(settings.llm)
        cache = ResponseCache(data_dir() / "cache.sqlite") if settings.scan.use_cache else None
        return LLMClient(provider, cache, settings.scan.max_llm_calls, settings.llm.max_concurrency)

    @staticmethod
    def _apply_project_scope(target: Target, settings: Settings) -> None:
        """Re-apply language/exclude filters after project overrides were read."""
        from .rules.engine import path_matches

        keep = []
        for f in target.files:
            if f.language not in settings.scan.languages:
                target.skipped.append({"file": f.rel_path, "reason": f"{f.language.value} disabled"})
            elif any(path_matches(f.rel_path, p) for p in settings.scan.exclude):
                target.skipped.append({"file": f.rel_path, "reason": "excluded by project config"})
            else:
                keep.append(f)
        target.files = keep

    async def _hunt(self, run, settings, index, signals, ruleset, repo_ctx, agents, categories, phase) -> list[_Candidate]:
        """Step 7: run Hunter agents with self-consistency voting."""
        chunks = index.chunks(settings.scan.chunk_max_lines)
        run.stats.chunks = len(chunks)
        if settings.scan.mode == "focused":
            chunks = [c for c in chunks if any(c.start_line <= s.line <= c.end_line for s in signals[c.file])]
        run.stats.chunks_analysed = len(chunks)

        if settings.scan.hunters == "specialist":
            groups = [[c for c in cats if c in categories] for cats in HUNTER_GROUPS.values()]
            groups = [g for g in groups if g]
        else:
            groups = [categories]
        votes = settings.scan.votes
        ai_rules = ruleset.ai_rules()
        total = max(1, len(chunks) * len(groups) * votes)
        done = 0
        lock = asyncio.Lock()

        async def one(chunk, group, vote):
            nonlocal done
            try:
                return await agents.hunt(chunk, group, signals[chunk.file], ai_rules, repo_ctx, vote)
            finally:
                async with lock:
                    done += 1
                    phase("hunter agents", 0.1 + 0.5 * done / total, done=done, total=total)

        jobs = [(c, g, v) for c in chunks for g in groups for v in range(votes)]
        results = await asyncio.gather(*(one(c, g, v) for c, g, v in jobs), return_exceptions=True)

        # Line-verify every raw finding, then vote per (chunk, group).
        per_key: dict[tuple, list[list[dict]]] = {}
        failed = 0
        for (chunk, group, vote), res in zip(jobs, results):
            key = (chunk.id, tuple(group))
            per_key.setdefault(key, [[] for _ in range(votes)])
            if isinstance(res, BaseException):
                if isinstance(res, ScanCancelled):
                    raise res
                failed += 1
                msg = f"hunter failed on {chunk.id}: {res}"
                if msg not in run.warnings:
                    run.warnings.append(msg)
                continue
            fi = index.files[chunk.file]
            for hf in res:
                cwe_n = parse_cwe(hf.cwe)
                if cwe_n is None:
                    continue
                line = verify_location(fi.redacted, hf.line, hf.evidence, chunk.start_line, chunk.end_line)
                if line is None:
                    run.stats.hallucinated_lines_dropped += 1
                    continue
                shift = line - hf.line
                end_line = max(line, (hf.end_line or hf.line) + shift)
                per_key[key][vote].append(
                    {"file": chunk.file, "line": line, "end_line": min(end_line, line + 20), "cwe": cwe_label(cwe_n),
                     "title": hf.title, "reason": hf.reason, "source": hf.source, "related_rule": hf.related_rule}
                )

        if jobs and failed == len(jobs):
            # Every AI call failed: say so plainly at the top of the warnings,
            # otherwise the results look like a normal (but thin) AI scan.
            run.warnings.insert(0, f"AI analysis failed for every code chunk, so only pattern-rule matches are "
                                   f"reported (as unverified). First error: {next(r for r in results if isinstance(r, BaseException))}")
        merged: list[_Candidate] = []
        for vote_runs in per_key.values():
            for rep, count in vote_merge(vote_runs, votes):
                dup = next((m for m in merged if same_issue(m.file, m.line, m.cwe, rep["file"], rep["line"], rep["cwe"])), None)
                if dup is not None:
                    dup.votes = max(dup.votes, count)
                    continue
                cand = _Candidate(rep["file"], rep["line"], rep["end_line"], rep["cwe"], rep["title"][:200],
                                  rep["reason"], rep["source"], "ai", votes=count, vote_total=votes)
                if rep.get("related_rule") and ruleset.get(rep["related_rule"]):
                    cand.rule = ruleset.get(rep["related_rule"])
                merged.append(cand)
        return merged

    @staticmethod
    def _merge_rule_signals(cands: list[_Candidate], signals: dict[str, list[Signal]], ruleset: RuleSet) -> list[_Candidate]:
        """Step 8: `report` pattern matches become candidates, or enrich an AI
        candidate already pointing at the same line and CWE."""
        out = list(cands)
        for rel in sorted(signals):
            for s in signals[rel]:
                if s.rule_type != RuleType.PATTERN.value or s.mode != RuleMode.REPORT.value or not s.cwe:
                    continue
                rule = ruleset.get(s.rule_id)
                match = next((c for c in out if same_issue(c.file, c.line, c.cwe, s.file, s.line, s.cwe)), None)
                if match is not None:
                    if match.detector == "ai":
                        match.detector = "ai+rule"
                    # A custom rule beats a built-in one on the same issue: its
                    # message and remediation are specific to the user's code base.
                    if match.rule is None or (rule is not None and match.rule.origin == "builtin"
                                              and rule.origin != "builtin"):
                        if match.detector == "rule" and rule is not None:
                            match.title, match.reason = rule.name, s.message
                        match.rule = rule
                    continue
                out.append(_Candidate(s.file, s.line, s.line, s.cwe, rule.name if rule else s.rule_id,
                                      s.message, None, "rule", rule=rule))
        return out

    @staticmethod
    def _to_finding(c: _Candidate, fi: FileIndex) -> Finding:
        fn = fi.outer_function(c.line)
        fn_name = fn.qualified if fn else None
        fp = fingerprint(c.file, c.cwe, fn_name, fi.lines[c.line - 1])
        start, end = fi.window_for(c.line, max_lines=120)
        cwe_n = parse_cwe(c.cwe)
        refs = [u for u in [mitre_url(cwe_n)] if u]
        if c.rule is not None:
            refs += [r for r in c.rule.references if r not in refs]
        return Finding(
            id=finding_id(fp),
            fingerprint=fp,
            status="unverified",
            title=c.title,
            cwe=c.cwe,
            cwe_name=cwe_name(cwe_n),
            owasp=owasp_for(cwe_n),
            severity=c.rule.severity.value if c.rule else "medium",
            confidence=c.rule.confidence if c.rule else 0.5,
            votes=f"{c.votes}/{c.vote_total}" if c.detector != "rule" else None,
            detector=c.detector,  # type: ignore[arg-type]
            rule_id=c.rule.id if c.rule else None,
            language=fi.source.language.value,
            file=c.file,
            start_line=c.line,
            end_line=max(c.line, c.end_line),
            snippet=fi.redacted[c.line - 1].strip()[:500],
            function=fn_name,
            explanation=c.reason,
            references=refs,
            code_context=CodeContext(start_line=start, lines=fi.redacted[start - 1 : end]),
        )

    @staticmethod
    def _rules_only(findings: list[tuple[Finding, _Candidate]]) -> None:
        for f, c in findings:
            if c.rule is not None and c.rule.remediation:
                f.remediation = Remediation(summary=c.rule.remediation, guidance_only=True)
            if f.status != "suppressed":
                f.status = "unverified"

    async def _verify_all(self, run, settings, index, findings, repo_ctx, agents, phase) -> None:
        """Step 9: Tracer -> Verifier -> Remediator for each candidate."""
        todo = [(f, c) for f, c in findings if f.status != "suppressed"]
        total = max(1, len(todo))
        done = 0
        lock = asyncio.Lock()

        async def one(f: Finding, c: _Candidate) -> None:
            nonlocal done
            try:
                await self._verify_one(run, settings, index.files[f.file], f, c, repo_ctx, agents)
            except (LLMError, BudgetExceeded) as exc:
                f.status = "unverified"
                f.meta["verification_error"] = str(exc)[:300]
                msg = f"could not verify {f.id}: {exc}"
                if len(run.warnings) < 50:
                    run.warnings.append(msg)
            finally:
                async with lock:
                    done += 1
                    phase("tracer / verifier / remediator agents", 0.62 + 0.33 * done / total, done=done, total=total)

        await asyncio.gather(*(one(f, c) for f, c in todo))

    async def _verify_one(self, run, settings, fi: FileIndex, f: Finding, c: _Candidate, repo_ctx, agents: Agents) -> None:
        rule = c.rule
        # Rules marked verify:false (e.g. committed private keys) are certain
        # enough that no LLM opinion is needed.
        if c.detector == "rule" and rule is not None and not rule.verify:
            f.status = "confirmed"
            f.explanation = rule.message
            if rule.remediation:
                f.remediation = Remediation(summary=rule.remediation, guidance_only=True)
            return

        trace: TraceResult | None = None
        if settings.scan.trace and settings.scan.tool_budget > 0:
            try:
                trace = await agents.trace(f.file, f.start_line, f.title, f.cwe or "", c.reason)
                f.data_flow = trace.data_flow
            except (LLMError, BudgetExceeded) as exc:
                f.meta["trace_error"] = str(exc)[:300]

        ctx = f.code_context
        assert ctx is not None
        v = await agents.verify(
            title=f.title, cwe=f.cwe or "", cwe_name=f.cwe_name, path=f.file, line=f.start_line,
            function=f.function, detector=f.detector, reason=c.reason, rule=rule, trace=trace,
            window_start=ctx.start_line, window_lines=ctx.lines, repo_ctx=repo_ctx, user_answer=f.context_answer,
        )
        self._apply_verdict(f, v, c.votes, c.vote_total)

        if f.status in ("confirmed", "needs_context") and settings.remediation.enabled:
            await self._remediate(f, fi, rule, agents)

    @staticmethod
    def _apply_verdict(f: Finding, v, votes: int, vote_total: int) -> None:
        f.status = v.verdict
        f.title = v.title[:200] or f.title
        new_cwe = parse_cwe(v.cwe)
        if new_cwe is not None and cwe_label(new_cwe) != f.cwe:
            f.meta["cwe_from_hunter"] = f.cwe
            f.cwe, f.cwe_name, f.owasp = cwe_label(new_cwe), cwe_name(new_cwe), owasp_for(new_cwe)
            url = mitre_url(new_cwe)
            if url and url not in f.references:
                f.references.insert(0, url)
        f.explanation = v.explanation
        f.exploit_scenario = v.exploit_scenario
        f.impact = v.impact
        if v.existing_controls:
            f.meta["existing_controls"] = v.existing_controls[:1000]
        f.context_question = v.context_question if v.verdict == "needs_context" else None
        f.severity_factors = SeverityFactors(**v.severity_factors.model_dump())
        f.severity = compute_severity(f.severity_factors)
        ratio = votes / vote_total if vote_total else 1.0
        f.confidence = round(v.confidence * (0.7 + 0.3 * ratio), 2)

    @staticmethod
    async def _remediate(f: Finding, fi: FileIndex, rule: Rule | None, agents: Agents) -> None:
        start, end = fi.window_for(f.start_line, max_lines=160)
        try:
            r = await agents.remediate(
                title=f.title, cwe=f.cwe or "", path=f.file, line=f.start_line, language=f.language,
                explanation=f.explanation, rule=rule, window_start=start, window_lines=fi.redacted[start - 1 : end],
            )
        except (LLMError, BudgetExceeded) as exc:
            f.meta["remediation_error"] = str(exc)[:300]
            if rule is not None and rule.remediation:
                f.remediation = Remediation(summary=rule.remediation, guidance_only=True)
            return
        res = build_patch(
            original_text=fi.source.text, redacted_lines=fi.redacted, rel_path=f.file,
            language=fi.source.language, flagged_line=f.start_line, start=r.start_line, end=r.end_line,
            fixed_code=r.fixed_code, new_imports=r.new_imports, window=(start, end),
        )
        f.remediation = remediation_from(res, r.summary, r.start_line, r.end_line, r.fixed_code, r.new_imports, r.notes)

    @staticmethod
    def _finalise(run: ScanRun, settings: Settings, findings: list[tuple[Finding, _Candidate]], categories: list[str]) -> list[Finding]:
        edition = settings.scan.owasp_edition
        selected = set(settings.scan.categories)
        min_rank = severity_rank(settings.scan.min_severity)
        best: dict[str, Finding] = {}
        order = {"confirmed": 0, "needs_context": 1, "unverified": 2, "suppressed": 3, "rejected": 4}
        for f, _c in findings:
            cwe_n = parse_cwe(f.cwe)
            if settings.scan.strict_taxonomy and not is_known_cwe(cwe_n):
                continue
            if selected and f.owasp.get(edition) not in selected:
                continue
            # Text aimed at AI reviewers (possible prompt injection) is always
            # shown, whatever the severity floor: it is a warning about the scan.
            always_show = f.cwe == "CWE-1427"
            if (f.status in ("confirmed", "needs_context", "unverified") and not always_show
                    and severity_rank(f.severity) < min_rank):
                continue
            f.meta.setdefault("prompt_version", PROMPT_VERSION)
            if run.model:
                f.meta.setdefault("model", f"{run.provider}:{run.model}")
            prev = best.get(f.fingerprint)
            if prev is None or order[f.status] < order[prev.status]:
                best[f.fingerprint] = f
        return sorted(best.values(), key=lambda x: x.sort_key())

    @staticmethod
    def _unflagged(signals: dict[str, list[Signal]], findings: list[Finding]) -> list[dict]:
        """Sinks / report-rule matches no finding covers (shown for transparency,
        so an injected 'report nothing' cannot silently hide a dangerous sink)."""
        out = []
        for rel in sorted(signals):
            for s in signals[rel]:
                if s.rule_type not in ("sink", "pattern") or (s.rule_type == "pattern" and s.mode != "report"):
                    continue
                if any(f.file == rel and abs(f.start_line - s.line) <= 3 for f in findings):
                    continue
                out.append({"file": rel, "line": s.line, "rule_id": s.rule_id, "cwe": s.cwe, "text": s.text[:200]})
                if len(out) >= 200:
                    return out
        return out

    # ------------------------------------------------------- re-verification
    async def reverify_async(self, run_id: str, finding_ref: str, answer: str,
                             llm_client: LLMClient | None = None) -> Finding:
        """Answer a needs-context question and re-run the Verifier (and the
        Remediator if the finding is now confirmed) for that finding only."""
        run = self.store.load(run_id)
        f = run.finding(finding_ref)
        if f is None:
            raise KeyError(f"finding {finding_ref!r} not in run {run.id}")
        ContextStore(run.target_key).set_answer(f.fingerprint, f.context_question, answer)
        f.context_answer = answer.strip()
        settings = load_settings()
        llm = llm_client or self._make_llm(settings)
        agents = Agents(llm, settings)
        try:
            repo_ctx = RepoContext.from_dict(run.repo_context)
            trace = TraceResult(f.data_flow, "", False) if f.data_flow else None
            ctx = f.code_context or CodeContext(start_line=f.start_line, lines=[f.snippet])
            v = await agents.verify(
                title=f.title, cwe=f.cwe or "", cwe_name=f.cwe_name, path=f.file, line=f.start_line,
                function=f.function, detector=f.detector, reason=f.explanation, rule=None, trace=trace,
                window_start=ctx.start_line, window_lines=ctx.lines, repo_ctx=repo_ctx, user_answer=f.context_answer,
            )
            votes = f.votes.split("/") if f.votes else ["1", "1"]
            self._apply_verdict(f, v, int(votes[0]), int(votes[1]))
            f.meta["reverified_at"] = utcnow()
            if f.status in ("confirmed", "needs_context") and not f.remediation.fixed_code and settings.remediation.enabled:
                fi = self._file_index_if_unchanged(run, f.file)
                if fi is not None:
                    await self._remediate(f, fi, None, agents)
        finally:
            if llm_client is None:
                await llm.aclose()
        run.findings.sort(key=lambda x: x.sort_key())
        self.store.save(run)
        return f

    def reverify(self, run_id: str, finding_ref: str, answer: str) -> Finding:
        return asyncio.run(self.reverify_async(run_id, finding_ref, answer))

    @staticmethod
    def _file_index_if_unchanged(run: ScanRun, rel: str) -> FileIndex | None:
        if not run.target_root:
            return None
        from .security import sha256_text
        from .targets import SourceFile, detect_language

        path = Path(run.target_root) / rel
        if not path.is_file():
            return None
        text = path.read_text("utf-8", "replace")
        if sha256_text(text) != run.file_hashes.get(rel):
            return None
        lang = detect_language(path) or Language.PYTHON
        idx = CodeIndex([SourceFile(rel, path, lang, text, text.splitlines(), sha256_text(text))])
        return idx.files[rel]


def fail_threshold_hit(run: ScanRun, fail_on: str | None) -> bool:
    """CI gate: any active finding at or above `fail_on` severity."""
    if not fail_on:
        return False
    rank = SEVERITY_ORDER.index(fail_on)
    return any(severity_rank(f.severity) >= rank for f in run.active_findings())
