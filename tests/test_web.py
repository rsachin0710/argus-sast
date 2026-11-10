"""Web UI security layer and main endpoints."""

import pytest
from fastapi.testclient import TestClient

from argus.web.app import create_app

HOST = "127.0.0.1:8765"


@pytest.fixture
def client():
    app, token = create_app(port=8765, token="t0ken")
    c = TestClient(app, base_url=f"http://{HOST}")
    return c, token


def _login(c):
    r = c.get("/?token=t0ken", follow_redirects=False)
    assert r.status_code == 303
    return c


def _csrf(c):
    import re

    html = c.get("/").text
    return re.search(r'name="argus-csrf" content="([0-9a-f]+)"', html).group(1)


def test_requires_token(client):
    c, _ = client
    assert c.get("/").status_code == 401
    assert c.get("/?token=wrong").status_code == 401
    assert c.get("/api/runs").status_code == 401


def test_rejects_foreign_host_header(client):
    c, _ = client
    _login(c)
    assert c.get("/", headers={"host": "attacker.example:8765"}).status_code == 400


def test_security_headers(client):
    c, _ = client
    r = _login(c).get("/")
    assert r.status_code == 200
    assert "script-src 'self'" in r.headers["content-security-policy"]
    assert r.headers["x-frame-options"] == "DENY"
    assert r.headers["x-content-type-options"] == "nosniff"


def test_post_needs_csrf_and_same_origin(client):
    c, _ = client
    _login(c)
    body = {"target": "/nope", "ai": False}
    assert c.post("/api/scans", json=body).status_code == 403
    tok = _csrf(c)
    assert c.post("/api/scans", json=body, headers={"x-argus-csrf": tok, "origin": "https://evil.example"}).status_code == 403
    r = c.post("/api/scans", json=body, headers={"x-argus-csrf": tok, "origin": f"http://{HOST}"})
    assert r.status_code == 200 and r.json()["run_id"]


def test_scan_from_ui_and_pages_render(client, vuln_copy):
    import time

    c, _ = client
    _login(c)
    tok = _csrf(c)
    run_id = c.post("/api/scans", json={"target": str(vuln_copy), "ai": False},
                    headers={"x-argus-csrf": tok}).json()["run_id"]
    for _ in range(100):
        st = c.get(f"/api/runs/{run_id}/status").json()
        if st["status"] not in ("running", "queued"):
            break
        time.sleep(0.1)
    assert st["status"] == "completed"
    page = c.get(f"/runs/{run_id}")
    assert page.status_code == 200 and 'id="run-data"' in page.text
    for path in ("/", "/scan/new", "/rules", "/settings", "/context"):
        assert c.get(path).status_code == 200, path
    assert c.get(f"/api/runs/{run_id}/report/sarif").status_code == 200


def test_ai_scan_without_key_is_refused(client):
    c, _ = client
    _login(c)
    r = c.post("/api/scans", json={"target": "/x", "ai": True, "provider": "openai"},
               headers={"x-argus-csrf": _csrf(c)})
    assert r.status_code == 400 and "No API key" in r.json()["detail"]


def test_upload_only_allows_supported_files(client):
    c, _ = client
    _login(c)
    r = c.post("/api/scans", json={"ai": False, "upload": {"name": "evil.sh", "content": "rm -rf /"}},
               headers={"x-argus-csrf": _csrf(c)})
    assert r.status_code == 400


def test_custom_rule_via_api(client):
    c, _ = client
    _login(c)
    tok = _csrf(c)
    bad = c.post("/api/rules/validate", json={"yaml": "rules:\n  - id: x\n"}, headers={"x-argus-csrf": tok}).json()
    assert not bad["ok"]
    r = c.post("/api/rules", json={"rule": {"id": "acme.js.foo", "type": "pattern", "cwe": "CWE-79",
                                            "languages": ["javascript"], "patterns": "foo\\(\nbar\\("}},
               headers={"x-argus-csrf": tok})
    assert r.status_code == 200
    ids = {x["id"] for x in c.get("/api/rules").json()["rules"]}
    assert "acme.js.foo" in ids
    assert c.post("/api/rules/acme.js.foo/delete", headers={"x-argus-csrf": tok}).status_code == 200


def test_settings_validation(client):
    c, _ = client
    _login(c)
    tok = _csrf(c)
    assert c.post("/api/settings", json={"settings": {"llm": {"provider": "gemini"}}},
                  headers={"x-argus-csrf": tok}).status_code == 400
    assert c.post("/api/settings", json={"settings": {"scan": {"votes": 5}}},
                  headers={"x-argus-csrf": tok}).status_code == 200
