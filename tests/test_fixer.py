"""Consent-gated fixes."""

import json

import pytest

from argus.config import data_dir
from argus.fixer import FixError, apply_fix, plan_fix
from argus.pipeline import ScanOptions, ScanService


@pytest.fixture
def scanned(vuln_copy, fake_client):
    svc = ScanService()
    run = svc.run(ScanOptions(target=str(vuln_copy), llm_client=fake_client()))
    f = next(x for x in run.findings if x.file == "python/app.py" and x.start_line == 26)
    return svc.store, run, f, vuln_copy / "python" / "app.py"


def test_fix_requires_explicit_consent(scanned):
    store, run, f, path = scanned
    before = path.read_text()
    for bad in ("", "yes", "ARG-00000000"):
        with pytest.raises(FixError, match="consent"):
            apply_fix(store, run.id, f.id, confirm=bad)
    assert path.read_text() == before


def test_fix_applies_one_change_with_backup_and_audit(scanned):
    store, run, f, path = scanned
    before = path.read_text()
    apply_fix(store, run.id, f.id, confirm=f.id)
    after = path.read_text()
    assert 'cur.execute("SELECT * FROM users WHERE name = ?", (name,))' in after.splitlines()[25]
    assert (path.parent / "app.py.argus-bak").read_text() == before
    diff = [a for a, b in zip(before.splitlines(), after.splitlines()) if a != b]
    assert len(diff) == 1  # only the flagged line changed
    entry = json.loads((data_dir() / "audit.log").read_text().splitlines()[-1])
    assert entry["finding"] == f.id and entry["event"] == "fix_applied"
    assert store.load(run.id).finding(f.id).remediation.applied
    with pytest.raises(FixError, match="already applied"):
        apply_fix(store, run.id, f.id, confirm=f.id)


def test_second_fix_in_same_file_is_relocated(scanned):
    store, run, f, path = scanned
    apply_fix(store, run.id, f.id, confirm=f.id)
    other = next(x for x in run.findings if x.file == "python/app.py" and x.remediation.patch_valid and x.id != f.id)
    plan = plan_fix(store.load(run.id), other.id)
    assert plan.how == "by-line" or plan.how == "relocated"
    apply_fix(store, run.id, other.id, confirm=other.id)


def test_fix_refused_when_code_changed_at_location(scanned):
    store, run, f, path = scanned
    path.write_text(path.read_text().replace("cur.execute(f\"SELECT", "cur.execute(f\"select"))
    with pytest.raises(FixError, match="changed since the scan"):
        plan_fix(run, f.id)


def test_fix_refused_for_temporary_clone(scanned):
    store, run, f, path = scanned
    run.target_root = None
    with pytest.raises(FixError, match="temporary clone"):
        plan_fix(run, f.id)
