"""End-to-end scans (rules-only and with the scripted fake LLM)."""

import json

import pytest

from argus.config import Settings
from argus.pipeline import ScanOptions, ScanService, fail_threshold_hit
from argus.security import sha256_file


def _hashes(root):
    return {p: sha256_file(p) for p in root.rglob("*") if p.is_file()}


def test_rules_only_scan_finds_planted_bugs_and_not_safe_code(vuln_copy):
    run = ScanService().run(ScanOptions(target=str(vuln_copy), ai=False))
    assert run.status == "completed", run.errors
    locs = {(f.file, f.start_line, f.cwe) for f in run.findings}
    assert ("python/app.py", 26, "CWE-89") in locs
    assert ("java/UserController.java", 29, "CWE-89") in locs
    assert ("javascript/server.js", 18, "CWE-89") in locs
    # Parameterised queries are not reported.
    assert not any(f.file == "python/app.py" and f.start_line == 35 for f in run.findings)
    assert not any(f.file == "javascript/server.js" and f.start_line == 24 for f in run.findings)
    assert all(f.status == "unverified" for f in run.findings)
    assert all(f.owasp["2025"] or f.cwe == "CWE-1427" for f in run.findings)


def test_single_file_target(vuln_copy):
    run = ScanService().run(ScanOptions(target=str(vuln_copy / "python" / "app.py"), ai=False))
    assert run.target_kind == "file" and run.stats.files_scanned == 1
    assert run.findings


def test_unsupported_file_is_refused(tmp_path):
    p = tmp_path / "main.go"
    p.write_text("package main")
    run = ScanService().run(ScanOptions(target=str(p), ai=False))
    assert run.status == "failed" and "only Java, Python and JavaScript" in run.errors[0]


def test_ai_scan_end_to_end_and_never_modifies_code(vuln_copy, fake_client):
    before = _hashes(vuln_copy)
    run = ScanService().run(ScanOptions(target=str(vuln_copy), llm_client=fake_client(drop_on_vote=1)))
    assert run.status == "completed", run.errors
    assert _hashes(vuln_copy) == before, "a scan must never change the scanned code"

    by_loc = {(f.file, f.start_line): f for f in run.findings}
    sqli = by_loc[("python/app.py", 26)]
    assert sqli.status == "confirmed" and sqli.detector == "ai+rule" and sqli.votes == "3/3"
    assert sqli.remediation.patch_valid and "(name,)" in sqli.remediation.patch
    # Majority voting keeps an issue one vote missed (2 of 3).
    assert by_loc[("java/UserController.java", 80)].votes == "2/3"
    # Hallucinated evidence is dropped, not reported.
    assert run.stats.hallucinated_lines_dropped > 0
    assert not any(f.title == "Hallucinated" for f in run.findings)
    # Needs-context flow.
    ssrf = by_loc[("python/app.py", 70)]
    assert ssrf.status == "needs_context" and "internet" in ssrf.context_question
    # Verifier rejection is kept for transparency but not active.
    md5 = by_loc[("java/UserController.java", 73)]
    assert md5.status == "rejected" and md5 not in run.active_findings()
    # Tracer data flow lines are validated (the fake's bogus line 99999 is dropped).
    assert all(s.line < 1000 for f in run.findings for s in f.data_flow)
    # Severity comes from the formula.
    assert sqli.severity == "critical"


def test_reports_written(vuln_copy, fake_client, tmp_path):
    out = tmp_path / "out"
    run = ScanService().run(ScanOptions(target=str(vuln_copy), llm_client=fake_client(),
                                        out_dir=str(out), overrides={"output": {"formats": ["sarif", "md"]}}))
    d = out / run.id
    data = json.loads((d / "findings.json").read_text())
    assert data["schema_version"] == "1.0" and len(data["findings"]) == len(run.findings)
    txt = (d / "report.txt").read_text()
    assert "Why it is flagged" in txt and "NEEDS YOUR INPUT" in txt
    sarif = json.loads((d / "findings.sarif").read_text())
    assert sarif["version"] == "2.1.0" and sarif["runs"][0]["results"]
    assert (d / "report.md").is_file()
    assert any((d / "patches").glob("*.patch"))


def test_results_are_identical_on_rescan_with_cache(vuln_copy, monkeypatch):
    """The content-addressed cache makes re-scans of unchanged code identical."""
    from fake_llm import FakeProvider

    from argus.config import data_dir
    from argus.llm import LLMClient, ResponseCache

    cache = ResponseCache(data_dir() / "cache.sqlite")
    p1 = FakeProvider()
    r1 = ScanService().run(ScanOptions(target=str(vuln_copy), llm_client=LLMClient(p1, cache)))
    p2 = FakeProvider()
    r2 = ScanService().run(ScanOptions(target=str(vuln_copy), llm_client=LLMClient(p2, cache)))
    strip = lambda r: [(f.id, f.status, f.severity, f.cwe, f.start_line) for f in r.findings]
    assert strip(r1) == strip(r2)
    assert p2.calls == []  # everything came from the cache
    assert r2.stats.llm_cache_hits > 0


def test_answering_a_question_reverifies(vuln_copy, fake_client):
    svc = ScanService()
    run = svc.run(ScanOptions(target=str(vuln_copy), llm_client=fake_client()))
    nc = next(f for f in run.findings if f.status == "needs_context")
    import asyncio

    updated = asyncio.run(svc.reverify_async(run.id, nc.id, "It is internet facing.", llm_client=fake_client()))
    assert updated.status == "confirmed" and updated.context_answer == "It is internet facing."
    # The answer is remembered for the next scan of the same target.
    run2 = svc.run(ScanOptions(target=str(vuln_copy), llm_client=fake_client()))
    assert run2.finding(nc.id).status == "confirmed"


def test_inline_suppression_and_baseline(vuln_copy):
    app = vuln_copy / "python" / "app.py"
    app.write_text(app.read_text().replace(
        "return pickle.loads(request.data)", "return pickle.loads(request.data)  # argus-ignore[CWE-502]"))
    svc = ScanService()
    run = svc.run(ScanOptions(target=str(vuln_copy), ai=False))
    pk = next(f for f in run.findings if f.start_line == 48 and f.file == "python/app.py")
    assert pk.status == "suppressed"
    from argus.store import write_baseline

    write_baseline(run, vuln_copy / ".argus-baseline.json")
    run2 = svc.run(ScanOptions(target=str(vuln_copy), ai=False))
    assert run2.active_findings() == []


def test_category_filter_and_fail_on(vuln_copy):
    run = ScanService().run(ScanOptions(target=str(vuln_copy), ai=False, overrides={"scan": {"categories": ["A05"]}}))
    assert run.findings and all(f.owasp["2025"] == "A05" for f in run.findings)
    assert fail_threshold_hit(run, "high") and not fail_threshold_hit(run, None)


def test_provider_is_restricted_to_four():
    for p in ("anthropic", "openai", "xai", "ollama"):
        Settings.model_validate({"llm": {"provider": p}})
    with pytest.raises(Exception):
        Settings.model_validate({"llm": {"provider": "gemini"}})


def test_project_config_cannot_redirect_llm(tmp_path, vuln_copy):
    from argus.config import load_settings

    (vuln_copy / ".argus.toml").write_text(
        '[llm]\nbase_url = "https://evil.example"\n[scan]\nmin_severity = "high"\n')
    s = load_settings(target_root=vuln_copy)
    assert s.llm.base_url is None and s.scan.min_severity == "high"
