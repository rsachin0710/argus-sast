"""Deterministic rule matching.

The engine runs every enabled pattern/source/sink/sanitizer rule over a file
and returns ``Signal`` objects. Signals are used three ways:

  * `report` pattern rules  -> become findings directly (rules-only mode) or
                               candidate findings for the Verifier agent;
  * `hint` / sink / source   -> printed next to the code in Hunter prompts so
                               the model looks hard at those lines;
  * all signals             -> decide which chunks are worth an LLM call when
                               scan.mode = "focused".

It also finds inline suppressions:  `// argus-ignore`, `# argus-ignore[CWE-89]`,
`# argus-ignore: rule-id` on the flagged line or the line above.
"""

from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass

from ..config import Language
from .loader import RuleSet
from .model import Rule, RuleMode, RuleType

MAX_LINE_LEN = 3000  # longer lines are minified/generated code: skip (also limits ReDoS)
_COMMENT_PREFIX = {
    Language.PYTHON: ("#",),
    Language.JAVA: ("//", "/*", "*"),
    Language.JAVASCRIPT: ("//", "/*", "*"),
}
_SUPPRESS_RE = re.compile(r"argus-ignore(?:\[([^\]]+)\]|:\s*([\w.,\- ]+))?", re.IGNORECASE)


@dataclass
class Signal:
    rule_id: str
    rule_type: str  # pattern | source | sink | sanitizer
    mode: str  # report | hint
    file: str
    line: int  # 1-based
    text: str  # the matched source line (stripped)
    cwe: str | None
    severity: str
    message: str

    def hint_line(self) -> str:
        label = {"source": "untrusted input", "sink": "dangerous sink", "sanitizer": "sanitizer"}.get(
            self.rule_type, "suspicious pattern"
        )
        cwe = f" {self.cwe}" if self.cwe else ""
        return f"line {self.line}: {label}{cwe} ({self.rule_id}) {self.message}".strip()


def path_matches(rel_path: str, pattern: str) -> bool:
    """Glob match where `**/x/**` also matches at the repo root."""
    rel = rel_path.replace("\\", "/")
    return fnmatch.fnmatch(rel, pattern) or fnmatch.fnmatch("/" + rel, pattern)


def _rule_applies_to_path(rule: Rule, rel_path: str) -> bool:
    if rule.include and not any(path_matches(rel_path, g) for g in rule.include):
        return False
    if rule.exclude and any(path_matches(rel_path, g) for g in rule.exclude):
        return False
    return True


class RuleEngine:
    def __init__(self, ruleset: RuleSet):
        self.ruleset = ruleset

    def scan_file(self, rel_path: str, language: Language, lines: list[str]) -> list[Signal]:
        rules = [
            r
            for r in self.ruleset.active(
                language, {RuleType.PATTERN, RuleType.SOURCE, RuleType.SINK, RuleType.SANITIZER}
            )
            if _rule_applies_to_path(r, rel_path)
        ]
        if not rules:
            return []
        signals: list[Signal] = []
        comment_prefixes = _COMMENT_PREFIX.get(language, ())
        file_text: str | None = None

        for rule in rules:
            if rule.scope == "file":
                # Whole-file rule: fires at each pattern match unless ANY
                # pattern-not matches anywhere in the file (e.g. "parser created
                # and the hardening feature is never set").
                if file_text is None:
                    file_text = "\n".join(lines)
                if any(rx.search(file_text) for rx in rule.not_regexes):
                    continue
                for rx in rule.regexes:
                    for m in rx.finditer(file_text):
                        line_no = file_text.count("\n", 0, m.start()) + 1
                        signals.append(self._signal(rule, rel_path, line_no, lines[line_no - 1]))
                continue

            for idx, line in enumerate(lines):
                if len(line) > MAX_LINE_LEN or not line.strip():
                    continue
                stripped = line.lstrip()
                if not rule.include_comments and stripped.startswith(comment_prefixes):
                    continue
                if not any(rx.search(line) for rx in rule.regexes):
                    continue
                if any(rx.search(line) for rx in rule.not_regexes):
                    continue
                signals.append(self._signal(rule, rel_path, idx + 1, line))

        # One signal per (rule, line); stable order for deterministic prompts.
        uniq = {(s.rule_id, s.line): s for s in signals}
        return sorted(uniq.values(), key=lambda s: (s.line, s.rule_id))

    @staticmethod
    def _signal(rule: Rule, rel_path: str, line_no: int, line: str) -> Signal:
        return Signal(
            rule_id=rule.id,
            rule_type=rule.type.value,
            mode=rule.mode.value,
            file=rel_path,
            line=line_no,
            text=line.strip()[:300],
            cwe=rule.cwe,
            severity=rule.severity.value,
            message=rule.message,
        )


def suppressions(lines: list[str]) -> dict[int, set[str]]:
    """Map line number -> suppression tokens ('*' = everything).

    A comment on line N suppresses findings on N; a comment that is alone on
    line N suppresses findings on N+1.
    """
    out: dict[int, set[str]] = {}
    for idx, line in enumerate(lines):
        m = _SUPPRESS_RE.search(line)
        if not m:
            continue
        raw = m.group(1) or m.group(2) or ""
        tokens = {t.strip().upper() for t in re.split(r"[,\s]+", raw) if t.strip()} or {"*"}
        line_no = idx + 1
        out.setdefault(line_no, set()).update(tokens)
        before = line[: m.start()].strip()
        if before in ("", "#", "//", "/*", "*"):
            out.setdefault(line_no + 1, set()).update(tokens)
    return out


def is_suppressed(supp: dict[int, set[str]], line: int, cwe: str | None, rule_id: str | None) -> bool:
    tokens = supp.get(line)
    if not tokens:
        return False
    if "*" in tokens:
        return True
    return bool((cwe and cwe.upper() in tokens) or (rule_id and rule_id.upper() in tokens))


def report_signals(signals: list[Signal]) -> list[Signal]:
    return [s for s in signals if s.rule_type == "pattern" and s.mode == RuleMode.REPORT.value]
