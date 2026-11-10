"""Safety helpers for handling untrusted code.

1. ``redact_lines``  — removes secrets BEFORE code is sent to an LLM provider.
   Redaction is per line and never changes the number of lines, so every line
   number the model reports still points at the right line of the real file.
2. ``fence_code``    — wraps code in labelled, nonce-tagged delimiters so the
   model can tell instructions (ours) from data (the scanned repo). Any text in
   the code that tries to close the fence early is neutralised.
3. ``safe_join``     — confines agent tool file access to the scan root
   (blocks ../ traversal and symlinks that escape the root).
"""

from __future__ import annotations

import hashlib
import os
import re
from pathlib import Path

# (name, compiled regex, group index holding the secret or 0 for whole match)
_SECRET_PATTERNS: list[tuple[str, re.Pattern, int]] = [
    ("aws_key", re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"), 0),
    ("github_token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"), 0),
    ("slack_token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}"), 0),
    ("stripe_key", re.compile(r"\b[sr]k_live_[0-9a-zA-Z]{24,}"), 0),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"), 0),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b"), 0),
    (
        "secret",
        re.compile(
            r"(?i)\b\w*?(?:password|passwd|pwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token|"
            r"client[_-]?secret|private[_-]?key)\w*[\"'\]]{0,2}\s*[:=]\s*[\"']([^\"'\s]{6,})[\"']"
        ),
        1,
    ),
]
_PEM_BEGIN = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")
_PEM_END = re.compile(r"-----END [A-Z ]*PRIVATE KEY-----")


def redact_lines(lines: list[str]) -> tuple[list[str], int]:
    """Return (redacted copy of lines, number of redactions)."""
    out: list[str] = []
    count = 0
    in_pem = False
    for line in lines:
        # A PEM private key block: every line from BEGIN to END is replaced.
        if in_pem or _PEM_BEGIN.search(line):
            if _PEM_BEGIN.search(line):
                in_pem = True
            if _PEM_END.search(line):
                in_pem = False
            indent = line[: len(line) - len(line.lstrip())]
            out.append(f"{indent}<REDACTED:private_key>")
            count += 1
            continue
        new = line
        for name, rx, group in _SECRET_PATTERNS:
            if group == 0:
                new, n = rx.subn(f"<REDACTED:{name}>", new)
                count += n
            else:
                def _sub(m: re.Match, _name=name, _g=group) -> str:
                    s, e = m.span(_g)
                    return m.group(0)[: s - m.start()] + f"<REDACTED:{_name}>" + m.group(0)[e - m.start():]

                new, n = rx.subn(_sub, new)
                count += n
        out.append(new)
    return out, count


def content_nonce(text: str) -> str:
    """Deterministic fence nonce (keeps prompts cache-stable). Code cannot
    contain its own hash, so it cannot forge the closing fence."""
    return hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()[:12]


def number_lines(lines: list[str], start_line: int) -> str:
    width = len(str(start_line + len(lines)))
    return "\n".join(f"{str(start_line + i).rjust(width)} | {line}" for i, line in enumerate(lines))


def fence_code(path: str, lines: list[str], start_line: int) -> str:
    """Wrap code lines (already redacted) in untrusted-data delimiters."""
    body_lines = [ln.replace("</untrusted_code", "<\\/untrusted_code") for ln in lines]
    body = number_lines(body_lines, start_line)
    nonce = content_nonce(path + "\n" + "\n".join(lines))
    return (
        f'<untrusted_code file="{path}" first_line="{start_line}" nonce="{nonce}">\n'
        f"{body}\n"
        f'</untrusted_code nonce="{nonce}">'
    )


class PathEscapeError(ValueError):
    pass


def safe_join(root: Path, rel: str) -> Path:
    """Resolve `rel` under `root`; refuse anything that escapes it."""
    root_resolved = root.resolve()
    candidate = (root_resolved / rel.lstrip("/\\")).resolve()
    if candidate != root_resolved and root_resolved not in candidate.parents:
        raise PathEscapeError(f"path {rel!r} is outside the scan root")
    return candidate


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", "surrogateescape")).hexdigest()


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def is_within(root: Path, path: Path) -> bool:
    try:
        rp = Path(os.path.realpath(path))
        rr = Path(os.path.realpath(root))
        return rp == rr or rr in rp.parents
    except OSError:
        return False
