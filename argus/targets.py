"""Resolve what to scan into a read-only list of source files.

Supported targets
-----------------
* single file          argus scan src/Login.java
* local folder         argus scan ./myapp            (honours .gitignore in git repos)
* GitHub repository    argus scan https://github.com/org/repo [--ref main]
* GitHub pull request  argus scan --github-pr org/repo#123   (changed files only)
* git diff             argus scan . --since origin/main     (changed files only)

Only Java, Python and JavaScript files are scanned; everything else is listed
as skipped with a reason. Remote repositories are shallow-cloned into a
temporary folder with git hooks disabled and are deleted after the scan.
"""

from __future__ import annotations

import base64
import os
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

import httpx

from .config import Language, Settings
from .rules.engine import path_matches
from .security import is_within, sha256_text

EXTENSIONS: dict[str, Language] = {
    ".java": Language.JAVA,
    ".py": Language.PYTHON,
    ".pyw": Language.PYTHON,
    ".js": Language.JAVASCRIPT,
    ".mjs": Language.JAVASCRIPT,
    ".cjs": Language.JAVASCRIPT,
    ".jsx": Language.JAVASCRIPT,
}
_SHEBANG = {"python": Language.PYTHON, "node": Language.JAVASCRIPT}
_GITHUB_URL = re.compile(
    r"^(?:https?://github\.com/|git@github\.com:|github:)([\w.-]+)/([\w.-]+?)(?:\.git)?"
    r"(?:/tree/([^/]+)(?:/(.*))?)?/?$"
)
_PR_SPEC = re.compile(r"^(?:https?://github\.com/)?([\w.-]+)/([\w.-]+?)(?:#|/pull/)(\d+)/?$")


class TargetError(RuntimeError):
    pass


@dataclass
class SourceFile:
    rel_path: str  # posix path relative to the target root
    abs_path: Path
    language: Language
    text: str
    lines: list[str]
    sha256: str


@dataclass
class Target:
    kind: str  # file | directory | github | github-pr
    display: str  # what the user typed, for reports
    root: Path
    files: list[SourceFile] = field(default_factory=list)
    skipped: list[dict] = field(default_factory=list)
    repo_url: str | None = None
    ref: str | None = None
    is_git: bool = False
    temp_dir: Path | None = None  # set for remote clones; deleted by cleanup()

    @property
    def is_temporary(self) -> bool:
        return self.temp_dir is not None

    @property
    def key(self) -> str:
        """Stable identity used to store context answers between scans."""
        return self.repo_url or str(self.root.resolve())

    def cleanup(self) -> None:
        if self.temp_dir is not None and self.temp_dir.exists():
            shutil.rmtree(self.temp_dir, ignore_errors=True)


# --------------------------------------------------------------------------- #
# Language detection
# --------------------------------------------------------------------------- #
def detect_language(path: Path) -> Language | None:
    lang = EXTENSIONS.get(path.suffix.lower())
    if lang is not None:
        return lang
    if path.suffix == "":
        try:
            with open(path, "rb") as fh:
                first = fh.readline(200).decode("utf-8", "ignore")
        except OSError:
            return None
        if first.startswith("#!"):
            for word, language in _SHEBANG.items():
                if word in first:
                    return language
    return None


# --------------------------------------------------------------------------- #
# Git helpers (hooks are always disabled; credentials go through env, not argv)
# --------------------------------------------------------------------------- #
def _git_env() -> dict:
    env = dict(os.environ)
    env["GIT_TERMINAL_PROMPT"] = "0"
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    configs = [("core.hooksPath", os.devnull)]
    if token:
        basic = base64.b64encode(f"x-access-token:{token}".encode()).decode()
        configs.append(("http.https://github.com/.extraHeader", f"Authorization: Basic {basic}"))
    env["GIT_CONFIG_COUNT"] = str(len(configs))
    for i, (k, v) in enumerate(configs):
        env[f"GIT_CONFIG_KEY_{i}"] = k
        env[f"GIT_CONFIG_VALUE_{i}"] = v
    return env


def _git(args: list[str], cwd: Path | None = None, check: bool = True) -> str:
    try:
        proc = subprocess.run(
            ["git", *args],
            cwd=str(cwd) if cwd else None,
            env=_git_env(),
            capture_output=True,
            text=True,
            timeout=600,
        )
    except FileNotFoundError as exc:
        raise TargetError("git is not installed; it is needed to scan GitHub repositories") from exc
    except subprocess.TimeoutExpired as exc:
        raise TargetError("git timed out") from exc
    if check and proc.returncode != 0:
        raise TargetError(f"git {' '.join(args[:2])} failed: {proc.stderr.strip()[:400]}")
    return proc.stdout


def _is_git_repo(path: Path) -> bool:
    try:
        return _git(["rev-parse", "--is-inside-work-tree"], cwd=path, check=False).strip() == "true"
    except TargetError:
        return False


def _git_listed_files(root: Path) -> list[str] | None:
    """Tracked + untracked-but-not-ignored files (i.e. .gitignore honoured)."""
    try:
        out = _git(["ls-files", "-co", "--exclude-standard", "-z"], cwd=root, check=True)
    except TargetError:
        return None
    return [p for p in out.split("\0") if p]


def _git_changed_since(root: Path, ref: str) -> set[str]:
    changed = _git(["diff", "--name-only", f"{ref}...HEAD"], cwd=root, check=True).splitlines()
    changed += _git(["diff", "--name-only"], cwd=root, check=False).splitlines()  # unstaged
    changed += _git(["diff", "--name-only", "--cached"], cwd=root, check=False).splitlines()
    return {c.strip() for c in changed if c.strip()}


# --------------------------------------------------------------------------- #
# File collection
# --------------------------------------------------------------------------- #
def _excluded(rel: str, settings: Settings) -> bool:
    return any(path_matches(rel, pat) for pat in settings.scan.exclude)


def _load_file(root: Path, rel: str, settings: Settings, target: Target) -> None:
    abs_path = root / rel
    if abs_path.is_symlink() and not is_within(root, abs_path):
        target.skipped.append({"file": rel, "reason": "symlink outside the scan root"})
        return
    if not abs_path.is_file():
        return
    language = detect_language(abs_path)
    if language is None:
        target.skipped.append({"file": rel, "reason": "unsupported language"})
        return
    if language not in settings.scan.languages:
        target.skipped.append({"file": rel, "reason": f"{language.value} disabled in settings"})
        return
    if _excluded(rel, settings):
        target.skipped.append({"file": rel, "reason": "excluded by pattern"})
        return
    size = abs_path.stat().st_size
    if size > settings.scan.max_file_bytes:
        target.skipped.append({"file": rel, "reason": f"larger than {settings.scan.max_file_bytes} bytes"})
        return
    raw = abs_path.read_bytes()
    if b"\0" in raw[:4096]:
        target.skipped.append({"file": rel, "reason": "binary file"})
        return
    text = raw.decode("utf-8", errors="replace")
    lines = text.splitlines()
    if lines and max(len(ln) for ln in lines) > 5000 and len(lines) < 20:
        target.skipped.append({"file": rel, "reason": "minified / generated code"})
        return
    target.files.append(
        SourceFile(rel_path=rel, abs_path=abs_path, language=language, text=text, lines=lines, sha256=sha256_text(text))
    )


def _collect_dir(target: Target, settings: Settings, only: set[str] | None = None) -> None:
    root = target.root
    rels: list[str]
    listed = _git_listed_files(root) if target.is_git else None
    if listed is not None:
        rels = listed
    else:
        rels = []
        for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
            rel_dir = os.path.relpath(dirpath, root).replace(os.sep, "/")
            rel_dir = "" if rel_dir == "." else rel_dir + "/"
            # Prune excluded directories early (node_modules can be huge).
            dirnames[:] = sorted(
                d for d in dirnames if not _excluded(f"{rel_dir}{d}/x", settings) and d != ".git"
            )
            rels.extend(f"{rel_dir}{f}" for f in sorted(filenames))
    for rel in sorted(rels):
        if only is not None and rel not in only:
            continue
        if detect_language(root / rel) is None:
            continue  # do not clutter the skipped list with READMEs, images, ...
        _load_file(root, rel, settings, target)


def _clone(url: str, ref: str | None) -> Path:
    tmp = Path(tempfile.mkdtemp(prefix="argus-clone-"))
    dest = tmp / "repo"
    args = ["clone", "--depth", "1", "--no-tags", "--single-branch"]
    if ref:
        args += ["--branch", ref]
    args += [url, str(dest)]
    try:
        _git(args)
    except TargetError:
        shutil.rmtree(tmp, ignore_errors=True)
        raise
    return tmp


def _pr_changed_files(owner: str, repo: str, number: int) -> set[str] | None:
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    headers = {"Accept": "application/vnd.github+json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    files: set[str] = set()
    try:
        for page in range(1, 31):
            r = httpx.get(
                f"https://api.github.com/repos/{owner}/{repo}/pulls/{number}/files",
                params={"per_page": 100, "page": page},
                headers=headers,
                timeout=30,
            )
            if r.status_code != 200:
                return None
            batch = r.json()
            files.update(f["filename"] for f in batch if f.get("status") != "removed")
            if len(batch) < 100:
                break
    except httpx.HTTPError:
        return None
    return files


def resolve_target(
    spec: str | None,
    settings: Settings,
    ref: str | None = None,
    github_pr: str | None = None,
    since: str | None = None,
) -> Target:
    """Turn the user's input into a Target with its files loaded."""
    # --- GitHub pull request -------------------------------------------------
    if github_pr:
        m = _PR_SPEC.match(github_pr.strip())
        if not m:
            raise TargetError("use --github-pr owner/repo#123 (or the PR URL)")
        owner, repo, number = m.group(1), m.group(2), int(m.group(3))
        url = f"https://github.com/{owner}/{repo}.git"
        tmp = _clone(url, None)
        root = tmp / "repo"
        _git(["fetch", "--depth", "1", "origin", f"pull/{number}/head:argus-pr-{number}"], cwd=root)
        _git(["checkout", "--quiet", f"argus-pr-{number}"], cwd=root)
        target = Target("github-pr", f"{owner}/{repo}#{number}", root, repo_url=url, ref=f"pull/{number}",
                        is_git=True, temp_dir=tmp)
        changed = _pr_changed_files(owner, repo, number)
        if changed is None:
            target.skipped.append({"file": "*", "reason": "could not list PR files via the GitHub API; scanned the whole tree"})
        _collect_dir(target, settings, only=changed)
        return target

    if not spec:
        raise TargetError("nothing to scan: pass a file, a folder or a GitHub URL")

    # --- GitHub repository URL ----------------------------------------------
    m = _GITHUB_URL.match(spec.strip())
    if m and not Path(spec).exists():
        owner, repo, tree_ref, subpath = m.groups()
        url = f"https://github.com/{owner}/{repo}.git"
        use_ref = ref or tree_ref
        tmp = _clone(url, use_ref)
        root = tmp / "repo"
        target = Target("github", spec, root, repo_url=url, ref=use_ref, is_git=True, temp_dir=tmp)
        if subpath:
            sub_root = root / subpath
            if not is_within(root, sub_root) or not sub_root.exists():
                target.cleanup()
                raise TargetError(f"path {subpath!r} not found in {owner}/{repo}")
            prefix = subpath.strip("/") + "/"
            _collect_dir(target, settings)
            target.files = [f for f in target.files if f.rel_path.startswith(prefix)]
        else:
            _collect_dir(target, settings)
        return target

    # --- Local file or folder ---------------------------------------------------
    path = Path(spec).expanduser()
    if not path.exists():
        raise TargetError(f"{spec!r} does not exist (and is not a GitHub URL)")
    if path.is_file():
        root = path.resolve().parent
        target = Target("file", spec, root)
        target.is_git = _is_git_repo(root)
        if detect_language(path) is None:
            raise TargetError(f"{path.name}: only Java, Python and JavaScript files are supported")
        _load_file(root, path.name, settings, target)
        if not target.files:
            reason = target.skipped[0]["reason"] if target.skipped else "unreadable"
            raise TargetError(f"{path.name} was skipped: {reason}")
        return target

    root = path.resolve()
    target = Target("directory", spec, root)
    target.is_git = _is_git_repo(root)
    if target.is_git:
        try:
            target.repo_url = _git(["config", "--get", "remote.origin.url"], cwd=root, check=False).strip() or None
        except TargetError:
            target.repo_url = None
    only = None
    if since:
        if not target.is_git:
            raise TargetError("--since needs a git repository")
        top = Path(_git(["rev-parse", "--show-toplevel"], cwd=root).strip())
        changed = _git_changed_since(top, since)
        prefix = os.path.relpath(root, top).replace(os.sep, "/")
        prefix = "" if prefix == "." else prefix + "/"
        only = {c[len(prefix):] for c in changed if c.startswith(prefix)}
    _collect_dir(target, settings, only=only)
    return target
