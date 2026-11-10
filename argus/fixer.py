"""Consent-gated fixes. This is the ONLY module in Argus that writes to
scanned source code, and it does so only through ``apply_fix``.

Consent rules enforced in code (not configuration):
  1. One finding per call; there is no "fix everything" entry point.
  2. The caller must pass ``confirm=<the finding id>``. The CLI obtains it by
     showing the diff and asking; the web UI by a dialog where the user
     confirms that id. A missing or different value refuses the fix.
  3. The target must be a local folder that still exists (never a temporary
     clone), and the path must resolve inside it.
  4. The code must be unchanged since the scan (hash match) or the original
     lines must be found exactly once; otherwise we refuse.
  5. A backup (<file>.argus-bak) is written first, or the change goes to a new
     git branch when requested.
  6. Every applied fix is appended to the audit log.
"""

from __future__ import annotations

import getpass
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

from .findings import ScanRun, utcnow
from .remediation import apply_fix_text
from .security import safe_join, sha256_text
from .store import RunStore, audit
from .targets import detect_language


class FixError(RuntimeError):
    pass


@dataclass
class FixPlan:
    run: ScanRun
    finding_id: str
    file: Path
    rel: str
    current_text: str
    new_text: str
    how: str
    diff: str


def plan_fix(run: ScanRun, finding_ref: str, target_root: str | None = None) -> FixPlan:
    """Compute (but do not write) the change for one finding."""
    f = run.finding(finding_ref)
    if f is None:
        raise FixError(f"finding {finding_ref!r} is not in run {run.id}")
    r = f.remediation
    if r.applied:
        raise FixError(f"{f.id} was already applied at {r.applied_at}")
    if not r.fixed_code or r.start_line is None or r.end_line is None:
        raise FixError(f"{f.id} has no machine-applicable fix (guidance only): {r.summary or 'no suggestion'}")
    if not r.patch_valid:
        raise FixError(f"{f.id}'s suggested fix failed validation ({r.validation_note}); apply it by hand")
    root_s = target_root or run.target_root
    if not root_s:
        raise FixError(
            "this scan was of a temporary clone; check the repository out locally and pass "
            "--target-root <path>, or apply the .patch file with `git apply`"
        )
    root = Path(root_s)
    if not root.is_dir():
        raise FixError(f"target folder {root} no longer exists")
    path = safe_join(root, f.file)
    if not path.is_file():
        raise FixError(f"{f.file} not found under {root}")

    current = path.read_text("utf-8", "replace")
    # Original region text = what the scan saw on those lines.
    scanned_hash = run.file_hashes.get(f.file)
    if scanned_hash == sha256_text(current):
        original_region = current.splitlines()[r.start_line - 1 : r.end_line]
    else:
        ctx = f.code_context
        if ctx is None:
            raise FixError("file changed since the scan and no original context was saved; re-scan first")
        off = r.start_line - ctx.start_line
        original_region = ctx.lines[off : off + (r.end_line - r.start_line + 1)]
        if any("<REDACTED" in ln for ln in original_region):
            raise FixError("file changed since the scan and the region contains redacted text; re-scan first")
    language = detect_language(path)
    if language is None:
        raise FixError("unsupported file type")
    try:
        new_text, how = apply_fix_text(current, original_region, r.start_line, r.end_line, r.fixed_code, r.new_imports, language)
    except ValueError as exc:
        raise FixError(str(exc)) from exc

    import difflib

    diff = "".join(difflib.unified_diff(current.splitlines(keepends=True), new_text.splitlines(keepends=True),
                                        fromfile=f"a/{f.file}", tofile=f"b/{f.file}"))
    return FixPlan(run, f.id, path, f.file, current, new_text, how, diff)


def apply_fix(
    store: RunStore,
    run_id: str,
    finding_ref: str,
    *,
    confirm: str,
    target_root: str | None = None,
    git_branch: bool = False,
    via: str = "cli",
) -> FixPlan:
    """Apply ONE fix after explicit confirmation. Returns the applied plan."""
    run = store.load(run_id)
    plan = plan_fix(run, finding_ref, target_root)
    if (confirm or "").strip().upper() != plan.finding_id.upper():
        raise FixError(f"consent not given: confirm must equal the finding id {plan.finding_id}")

    # Re-read right before writing: refuse if the file changed meanwhile.
    if plan.file.read_text("utf-8", "replace") != plan.current_text:
        raise FixError("the file changed while you were reviewing; run the command again")

    branch = None
    if git_branch:
        branch = _git_branch_and_commit(plan)
    else:
        backup = plan.file.with_name(plan.file.name + ".argus-bak")
        shutil.copy2(plan.file, backup)
        plan.file.write_text(plan.new_text, encoding="utf-8")

    f = run.finding(plan.finding_id)
    assert f is not None
    f.remediation.applied = True
    f.remediation.applied_at = utcnow()
    f.meta["applied_via"] = via
    if branch:
        f.meta["fix_branch"] = branch
    store.save(run)
    audit(
        {
            "event": "fix_applied",
            "user": _user(),
            "via": via,
            "run": run.id,
            "finding": plan.finding_id,
            "file": str(plan.file),
            "sha256_before": sha256_text(plan.current_text),
            "sha256_after": sha256_text(plan.new_text),
            "method": plan.how,
            "git_branch": branch,
        },
        store.run_dir(run.id),
    )
    return plan


def _user() -> str:
    try:
        return getpass.getuser()
    except Exception:  # pragma: no cover
        return "unknown"


def _git_branch_and_commit(plan: FixPlan) -> str:
    """Create argus/fix-<id>, write the change, commit only that file."""
    cwd = plan.file.parent
    branch = f"argus/fix-{plan.finding_id.lower()}"

    def git(*args: str) -> str:
        p = subprocess.run(["git", *args], cwd=cwd, capture_output=True, text=True)
        if p.returncode != 0:
            raise FixError(f"git {' '.join(args)} failed: {p.stderr.strip()[:300]}")
        return p.stdout

    if git("status", "--porcelain", "--", str(plan.file)).strip():
        raise FixError(f"{plan.rel} has uncommitted changes; commit or stash them, or apply without --branch")
    git("checkout", "-b", branch)
    plan.file.write_text(plan.new_text, encoding="utf-8")
    git("add", "--", str(plan.file))
    git("commit", "-m", f"fix({plan.finding_id}): apply Argus security fix", "--", str(plan.file))
    return branch
