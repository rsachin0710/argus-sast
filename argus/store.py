"""Persistence: scan runs, developer context answers, and baselines.

Layout under the data dir (~/.local/share/argus or $ARGUS_HOME/data):

    runs/<run-id>/run.json          full ScanRun (findings, stats, settings)
    runs/<run-id>/findings.json     + report.txt / findings.sarif / report.md
    runs/<run-id>/patches/*.patch   one suggested patch per finding (never applied)
    runs/<run-id>/audit.log         fixes applied for this run
    context/<target-hash>.json      answers to "needs context" questions + notes
    audit.log                       every fix ever applied (JSON lines)
    cache.sqlite                    LLM response cache

Nothing here is written inside the scanned repository.
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import threading
from datetime import datetime
from pathlib import Path

from .config import data_dir
from .findings import ScanRun, utcnow


def _atomic_write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + f".tmp{os.getpid()}{threading.get_ident()}")
    tmp.write_text(text, encoding="utf-8")
    os.replace(tmp, path)


class RunStore:
    def __init__(self, root: Path | None = None):
        self.root = root or (data_dir() / "runs")
        self.root.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

    @staticmethod
    def new_run_id() -> str:
        return datetime.now().strftime("%Y%m%d-%H%M%S-") + secrets.token_hex(2)

    def run_dir(self, run_id: str) -> Path:
        if not run_id or "/" in run_id or "\\" in run_id or run_id.startswith("."):
            raise ValueError("invalid run id")
        return self.root / run_id

    def save(self, run: ScanRun) -> Path:
        path = self.run_dir(run.id) / "run.json"
        with self._lock:
            _atomic_write(path, run.model_dump_json(indent=2))
        return path

    def load(self, run_id: str) -> ScanRun:
        if run_id in ("latest", "last"):
            runs = self.list()
            if not runs:
                raise FileNotFoundError("no scans yet")
            run_id = runs[0]["id"]
        path = self.run_dir(run_id) / "run.json"
        if not path.is_file():
            raise FileNotFoundError(f"run {run_id!r} not found")
        return ScanRun.model_validate_json(path.read_text(encoding="utf-8"))

    def list(self, limit: int = 200) -> list[dict]:
        """Newest first; light summaries (no findings) for the dashboard."""
        out = []
        for d in sorted(self.root.iterdir(), reverse=True):
            p = d / "run.json"
            if not p.is_file():
                continue
            try:
                run = ScanRun.model_validate_json(p.read_text(encoding="utf-8"))
            except Exception:
                continue
            out.append(
                {
                    "id": run.id,
                    "created_at": run.created_at,
                    "status": run.status,
                    "target": run.target,
                    "provider": run.provider,
                    "model": run.model,
                    "ai_enabled": run.ai_enabled,
                    "counts": run.counts(),
                    "files": run.stats.files_scanned,
                }
            )
            if len(out) >= limit:
                break
        return out

    def delete(self, run_id: str) -> None:
        import shutil

        shutil.rmtree(self.run_dir(run_id), ignore_errors=True)


class ContextStore:
    """Developer answers to needs-context questions, keyed per scan target.

    Answers are keyed by finding fingerprint, so they survive line moves and
    are reused on the next scan of the same repository.
    """

    def __init__(self, target_key: str, root: Path | None = None):
        digest = hashlib.sha256(target_key.encode()).hexdigest()[:24]
        self.path = (root or (data_dir() / "context")) / f"{digest}.json"
        self.target_key = target_key
        self.data = {"target": target_key, "notes": "", "answers": {}}
        if self.path.is_file():
            try:
                self.data.update(json.loads(self.path.read_text(encoding="utf-8")))
            except ValueError:
                pass

    @property
    def notes(self) -> str:
        return self.data.get("notes", "")

    def answer_for(self, fingerprint: str) -> str | None:
        entry = self.data["answers"].get(fingerprint)
        return entry.get("answer") if entry else None

    def set_answer(self, fingerprint: str, question: str | None, answer: str) -> None:
        self.data["answers"][fingerprint] = {"question": question, "answer": answer.strip()[:4000], "at": utcnow()}
        self.save()

    def set_notes(self, notes: str) -> None:
        self.data["notes"] = notes.strip()[:8000]
        self.save()

    def save(self) -> None:
        _atomic_write(self.path, json.dumps(self.data, indent=2))


def load_baseline(path: Path) -> set[str]:
    """A baseline is a list of accepted fingerprints (`argus baseline create`)."""
    if not path.is_file():
        return set()
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except ValueError:
        return set()
    items = data.get("fingerprints", []) if isinstance(data, dict) else data
    return {str(x.get("fingerprint") if isinstance(x, dict) else x) for x in items}


def write_baseline(run: ScanRun, path: Path) -> int:
    entries = [
        {"fingerprint": f.fingerprint, "id": f.id, "cwe": f.cwe, "file": f.file, "title": f.title}
        for f in run.findings
        if f.status in ("confirmed", "needs_context", "unverified")
    ]
    _atomic_write(path, json.dumps({"version": 1, "created_at": utcnow(), "run": run.id, "fingerprints": entries}, indent=2))
    return len(entries)


def audit(event: dict, run_dir: Path | None = None) -> None:
    line = json.dumps({"at": utcnow(), **event}) + "\n"
    for p in [data_dir() / "audit.log", *( [run_dir / "audit.log"] if run_dir else [] )]:
        p.parent.mkdir(parents=True, exist_ok=True)
        with open(p, "a", encoding="utf-8") as fh:
            fh.write(line)
