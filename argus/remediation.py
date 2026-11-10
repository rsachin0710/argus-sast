"""Turn a Remediator answer into a validated unified diff.

The model never writes diffs: it returns replacement text for a line range,
and Argus builds the patch itself. That makes patches mechanically correct and
lets us check them before anyone sees them:

  1. the replaced range must contain the flagged line and stay inside the
     window the model was shown;
  2. the range must not contain redacted secrets (the model never saw them, so
     its replacement would write "<REDACTED>" into the file);
  3. the patched file must still parse (Python: ast; Java/JS: tree-sitter);
  4. the flagged line's original text must be gone or changed.

A patch that fails a check is kept as "guidance only" with the reason.
This module only COMPUTES text; it never writes to the scanned code
(applying a fix is ``argus.fixer``'s job, and only after user consent).
"""

from __future__ import annotations

import ast
import difflib
import re
from dataclasses import dataclass

from .config import Language
from .findings import Remediation, normalise_code
from .index import has_syntax_error

_IMPORT_RE = {
    Language.PYTHON: re.compile(r"^(import|from)\s+\S+"),
    Language.JAVA: re.compile(r"^import\s+[\w.*]+;"),
    Language.JAVASCRIPT: re.compile(r"^(import\s|(const|let|var)\s+.*=\s*require\()"),
}


@dataclass
class PatchResult:
    patched_text: str | None
    patch: str | None
    valid: bool
    note: str


def _insert_imports(lines: list[str], imports: list[str], language: Language) -> list[str]:
    todo = [imp.rstrip() for imp in imports if imp.strip() and imp.strip() not in {ln.strip() for ln in lines}]
    if not todo:
        return lines
    rx = _IMPORT_RE[language]
    last = -1
    for i, ln in enumerate(lines[:300]):
        if rx.match(ln):
            last = i
    if last == -1:
        # After a Java `package` line / Python docstring+future imports; else at top.
        for i, ln in enumerate(lines[:50]):
            if language == Language.JAVA and ln.startswith("package "):
                last = i
        return lines[: last + 1] + todo + lines[last + 1 :]
    return lines[: last + 1] + todo + lines[last + 1 :]


def _reindent(fixed_lines: list[str], original_first: str) -> list[str]:
    """If the model dropped the leading indentation, restore it from the
    first original line (common with small models)."""
    if not fixed_lines:
        return fixed_lines
    want = original_first[: len(original_first) - len(original_first.lstrip())]
    have = fixed_lines[0][: len(fixed_lines[0]) - len(fixed_lines[0].lstrip())]
    if want and not have:
        return [(want + ln) if ln.strip() else ln for ln in fixed_lines]
    return fixed_lines


def build_patch(
    *,
    original_text: str,
    redacted_lines: list[str],
    rel_path: str,
    language: Language,
    flagged_line: int,
    start: int,
    end: int,
    fixed_code: str,
    new_imports: list[str],
    window: tuple[int, int],
) -> PatchResult:
    lines = original_text.splitlines()
    n = len(lines)
    if not (1 <= start <= end <= n):
        return PatchResult(None, None, False, f"line range {start}-{end} is outside the file (1-{n})")
    if not (start <= flagged_line <= end):
        return PatchResult(None, None, False, f"replacement {start}-{end} does not include the flagged line {flagged_line}")
    if start < window[0] or end > window[1]:
        return PatchResult(None, None, False, "replacement range is outside the code the model was shown")
    if any(lines[i] != redacted_lines[i] for i in range(start - 1, end)):
        return PatchResult(None, None, False, "the lines to replace contain redacted secrets; apply this fix by hand")
    if "<REDACTED" in fixed_code:
        return PatchResult(None, None, False, "the suggested code contains a redaction marker")

    fixed_lines = fixed_code.replace("\r\n", "\n").strip("\n").split("\n")
    fixed_lines = _reindent(fixed_lines, lines[start - 1])
    patched = lines[: start - 1] + fixed_lines + lines[end:]
    patched = _insert_imports(patched, new_imports, language)
    trailing_nl = original_text.endswith("\n")
    patched_text = "\n".join(patched) + ("\n" if trailing_nl else "")

    if patched_text == original_text:
        return PatchResult(None, None, False, "the suggestion does not change the code")

    # Syntax check (only meaningful if the original parsed cleanly).
    if language == Language.PYTHON:
        try:
            ast.parse(original_text)
            try:
                ast.parse(patched_text)
            except SyntaxError as exc:
                return PatchResult(patched_text, None, False, f"patched file does not parse: {exc.msg} (line {exc.lineno})")
        except SyntaxError:
            pass
    else:
        if not has_syntax_error(language, original_text) and has_syntax_error(language, patched_text):
            return PatchResult(patched_text, None, False, "patched file has a syntax error")

    old_flagged = normalise_code(lines[flagged_line - 1])
    if old_flagged and any(normalise_code(fl) == old_flagged for fl in fixed_lines):
        note = "the flagged line is unchanged by this fix; review carefully"
    else:
        note = "patch applies cleanly and the file still parses"

    diff = difflib.unified_diff(
        original_text.splitlines(keepends=True),
        patched_text.splitlines(keepends=True),
        fromfile=f"a/{rel_path}",
        tofile=f"b/{rel_path}",
        n=3,
    )
    patch = "".join(diff)
    if patch and not patch.endswith("\n"):
        patch += "\n\\ No newline at end of file\n"
    # An unchanged flagged line can be legitimate (e.g. a validation guard added
    # above it), so the patch stays valid; the note tells the reviewer to look.
    return PatchResult(patched_text, patch, True, note)


def remediation_from(result: PatchResult, summary: str, start: int, end: int, fixed_code: str,
                     new_imports: list[str], notes: str = "") -> Remediation:
    text = summary.strip()
    if notes.strip():
        text += ("\n\n" if text else "") + "Also: " + notes.strip()
    return Remediation(
        summary=text,
        start_line=start,
        end_line=end,
        fixed_code=fixed_code,
        new_imports=new_imports,
        patch=result.patch,
        patch_valid=result.valid and bool(result.patch),
        guidance_only=not (result.valid and result.patch),
        validation_note=result.note,
    )


def apply_fix_text(current_text: str, original_region: list[str], start: int, end: int,
                   fixed_code: str, new_imports: list[str], language: Language) -> tuple[str, str]:
    """Compute the new content for `argus fix`.

    If the file is unchanged since the scan, lines start..end are replaced
    directly. If it changed (e.g. another fix in the same file shifted lines),
    the original region is located by exact content; it must occur exactly
    once, otherwise we refuse rather than guess.
    Returns (new_text, how) where how is "by-line" or "relocated".
    """
    lines = current_text.splitlines()
    how = "by-line"
    if lines[start - 1 : end] != original_region:
        k = len(original_region)
        hits = [i for i in range(0, len(lines) - k + 1) if lines[i : i + k] == original_region]
        if len(hits) != 1:
            raise ValueError(
                "the code at this location changed since the scan and the original lines could not be "
                "found exactly once; re-scan the file before fixing"
            )
        start = hits[0] + 1
        end = start + k - 1
        how = "relocated"
    fixed_lines = _reindent(fixed_code.replace("\r\n", "\n").strip("\n").split("\n"), lines[start - 1])
    new_lines = _insert_imports(lines[: start - 1] + fixed_lines + lines[end:], new_imports, language)
    return "\n".join(new_lines) + ("\n" if current_text.endswith("\n") else ""), how
