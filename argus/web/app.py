"""Localhost web UI (FastAPI + server-rendered Jinja + a little vanilla JS).

Start it with `argus serve`; it binds to 127.0.0.1 on the port chosen in
`argus init`. The UI offers the same operations as the CLI and calls the same
modules (ScanService, rules loader, fixer), so results are identical.

How a request flows through the security layers (``_guard`` middleware)
-----------------------------------------------------------------------
1. Host header must be localhost/127.0.0.1/[::1] on our port (blocks DNS
   rebinding: a malicious site cannot point its own hostname at 127.0.0.1).
2. Session: a random token is printed in the terminal at start-up. Opening the
   `/?token=...` link sets an HttpOnly, SameSite=Strict cookie; every other
   request needs that cookie. The token changes on every restart.
3. State-changing requests (POST/DELETE) also need the X-Argus-CSRF header
   (an HMAC of the session token, given to our own pages only) and, if the
   browser sends one, an Origin that is our own origin.
4. Every response carries a strict CSP (no inline script), nosniff,
   no-referrer and frame-deny headers. All scanned code and LLM output is
   rendered with textContent / Jinja autoescape — never as HTML — because
   scanned repositories can contain XSS payloads.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import secrets
import shutil
import threading
from pathlib import Path

import yaml
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from .. import __version__
from ..config import (
    DEFAULT_MODELS,
    SEVERITY_ORDER,
    ProviderName,
    Settings,
    data_dir,
    load_settings,
    save_user_settings,
    user_rules_dir,
)
from ..credentials import key_status, set_api_key
from ..fixer import FixError, apply_fix, plan_fix
from ..pipeline import ScanOptions, ScanService
from ..reports import to_markdown, to_sarif, to_text, to_json
from ..rules import load_rules, parse_rule_data, save_custom_rule
from ..store import RunStore
from ..taxonomy import OWASP_2021_NAMES, OWASP_2025_NAMES

HERE = Path(__file__).parent
COOKIE = "argus_session"
_ALLOWED_UPLOAD = {".java", ".py", ".js", ".mjs", ".cjs", ".jsx"}
_SAFE_NAME = re.compile(r"[^A-Za-z0-9._-]")

CSP = (
    "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
    "connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"
)


class JobManager:
    """Runs scans in background threads; one cancel flag per run."""

    def __init__(self, service: ScanService):
        self.service = service
        self.jobs: dict[str, dict] = {}
        self._lock = threading.Lock()

    def start(self, opts: ScanOptions) -> str:
        run_id = opts.run_id or self.service.store.new_run_id()
        opts.run_id = run_id
        cancel = threading.Event()
        state = {"phase": "queued", "progress": 0.0, "status": "running", "cancel": cancel}

        def on_progress(event: str, data: dict) -> None:
            if event == "phase":
                state["phase"] = data["phase"] + (f" ({data['done']}/{data['total']})" if "done" in data else "")
                state["progress"] = data["progress"]
            elif event == "done":
                state["status"] = data["status"]
                state["progress"] = 1.0

        def work() -> None:
            try:
                self.service.run(opts, progress=on_progress, cancel=cancel)
            finally:
                state["status"] = state["status"] if state["status"] != "running" else "failed"

        with self._lock:
            self.jobs[run_id] = state
        # Write a "queued" record BEFORE the thread starts, so the run page the
        # browser is redirected to exists immediately.
        from ..findings import ScanRun

        self.service.store.save(ScanRun(id=run_id, target=opts.target or opts.github_pr or "",
                                        status="queued", phase="queued", ai_enabled=opts.ai))
        threading.Thread(target=work, name=f"argus-scan-{run_id}", daemon=True).start()
        return run_id

    def status(self, run_id: str) -> dict | None:
        s = self.jobs.get(run_id)
        return None if s is None else {k: v for k, v in s.items() if k != "cancel"}

    def cancel(self, run_id: str) -> bool:
        s = self.jobs.get(run_id)
        if s is None:
            return False
        s["cancel"].set()
        return True


def create_app(host: str = "127.0.0.1", port: int = 8765, token: str | None = None,
               store: RunStore | None = None) -> tuple[FastAPI, str]:
    token = token or secrets.token_urlsafe(24)
    csrf = hmac.new(token.encode(), b"argus-csrf", hashlib.sha256).hexdigest()
    store = store or RunStore()
    service = ScanService(store)
    jobs = JobManager(service)
    allowed_hosts = {f"127.0.0.1:{port}", f"localhost:{port}", f"[::1]:{port}"}
    if host not in ("127.0.0.1", "localhost", "::1", "0.0.0.0", "::"):
        allowed_hosts.add(f"{host}:{port}")
    allowed_origins = {f"http://{h}" for h in allowed_hosts}

    app = FastAPI(title="Argus", version=__version__, docs_url=None, redoc_url=None, openapi_url=None)
    app.mount("/static", StaticFiles(directory=str(HERE / "static")), name="static")
    templates = Jinja2Templates(directory=str(HERE / "templates"))
    templates.env.globals.update(version=__version__, csrf=csrf, sev_order=list(reversed(SEVERITY_ORDER)))
    templates.env.filters["short_target"] = _short_target

    # ------------------------------------------------------------- security
    @app.middleware("http")
    async def _guard(request: Request, call_next):
        # 1. Host allowlist (DNS-rebinding protection)
        if request.headers.get("host", "") not in allowed_hosts:
            return PlainTextResponse("Invalid Host header", status_code=400)
        # 2. Session token: ?token= sets the cookie once, then is stripped from the URL
        q_token = request.query_params.get("token")
        if q_token is not None and request.method == "GET":
            if hmac.compare_digest(q_token, token):
                resp = RedirectResponse(request.url.path or "/", status_code=303)
                resp.set_cookie(COOKIE, token, httponly=True, samesite="strict", path="/")
                return _secure(resp)
            return _secure(PlainTextResponse("Invalid token. Use the link printed by `argus serve`.", status_code=401))
        cookie = request.cookies.get(COOKIE, "")
        if not (cookie and hmac.compare_digest(cookie, token)):
            if request.url.path.startswith("/static/"):
                return await call_next(request)
            return _secure(HTMLResponse(_LOCKED_PAGE, status_code=401))
        # 3. CSRF for state-changing requests
        if request.method not in ("GET", "HEAD", "OPTIONS"):
            origin = request.headers.get("origin")
            if origin is not None and origin not in allowed_origins:
                return _secure(JSONResponse({"error": "cross-origin request refused"}, status_code=403))
            if not hmac.compare_digest(request.headers.get("x-argus-csrf", ""), csrf):
                return _secure(JSONResponse({"error": "missing or invalid CSRF token"}, status_code=403))
        return _secure(await call_next(request))

    def _secure(resp: Response) -> Response:
        resp.headers["Content-Security-Policy"] = CSP
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Referrer-Policy"] = "no-referrer"
        resp.headers["Cache-Control"] = "no-store"
        return resp

    def page(request: Request, name: str, **ctx) -> HTMLResponse:
        settings = load_settings()
        return templates.TemplateResponse(request, name, {"settings": settings, "active": name.split(".")[0], **ctx})

    def load_run(run_id: str):
        try:
            return store.load(run_id)
        except (FileNotFoundError, ValueError):
            raise HTTPException(404, "scan not found")

    # ---------------------------------------------------------------- pages
    @app.get("/", response_class=HTMLResponse)
    def dashboard(request: Request):
        return page(request, "dashboard.html", runs=store.list())

    @app.get("/scan/new", response_class=HTMLResponse)
    def new_scan(request: Request):
        return page(request, "new_scan.html", providers=[p.value for p in ProviderName],
                    default_models={p.value: m for p, m in DEFAULT_MODELS.items()},
                    owasp25=OWASP_2025_NAMES, owasp21=OWASP_2021_NAMES,
                    key_ok={p.value: key_status(p) != "not set" for p in ProviderName})

    @app.get("/runs/{run_id}", response_class=HTMLResponse)
    def run_page(request: Request, run_id: str):
        try:
            run = store.load(run_id)
        except (FileNotFoundError, ValueError):
            return HTMLResponse('<!doctype html><link rel="stylesheet" href="/static/style.css"><body class="locked">'
                                '<main class="locked-box"><h1>Scan not found</h1><p>It may have been deleted. '
                                '<a href="/">Back to scans</a></p></main>', status_code=404)
        names = OWASP_2025_NAMES if run.owasp_edition == "2025" else OWASP_2021_NAMES
        return page(request, "run.html", run=run, run_json=run.model_dump(mode="json"), owasp_names=names)

    @app.get("/context", response_class=HTMLResponse)
    def context_page(request: Request):
        items = []
        seen_targets: set[str] = set()
        for r in store.list(limit=40):
            if r["target"] in seen_targets or r["status"] != "completed":
                continue
            seen_targets.add(r["target"])
            run = store.load(r["id"])
            for f in run.findings:
                if f.status == "needs_context":
                    items.append({"run": run.id, "target": run.target, "f": f})
        return page(request, "context.html", items=items)

    @app.get("/rules", response_class=HTMLResponse)
    def rules_page(request: Request):
        rs = load_rules(load_settings())
        rules = sorted((r.summary() for r in rs.rules.values()), key=lambda s: (s["origin"] == "builtin", s["id"]))
        return page(request, "rules.html", rules=rules, errors=[str(e) for e in rs.errors],
                    rules_dir=str(user_rules_dir()))

    @app.get("/settings", response_class=HTMLResponse)
    def settings_page(request: Request):
        return page(request, "settings.html", providers=[p.value for p in ProviderName],
                    default_models={p.value: m for p, m in DEFAULT_MODELS.items()},
                    key_states={p.value: key_status(p) for p in ProviderName})

    # ------------------------------------------------------------------ API
    @app.get("/api/runs")
    def api_runs():
        return store.list()

    @app.get("/api/runs/{run_id}")
    def api_run(run_id: str):
        return load_run(run_id).model_dump(mode="json")

    @app.get("/api/runs/{run_id}/status")
    def api_status(run_id: str):
        live = jobs.status(run_id)
        run = load_run(run_id)
        if live and live["status"] == "running":
            return {"status": "running", "phase": live["phase"], "progress": live["progress"]}
        return {"status": run.status, "phase": run.phase, "progress": run.progress, "errors": run.errors}

    @app.post("/api/scans")
    async def api_start_scan(request: Request):
        body = await request.json()
        target = (body.get("target") or "").strip() or None
        pr = (body.get("github_pr") or "").strip() or None
        if body.get("upload"):
            target = _save_upload(body["upload"])
        if not target and not pr:
            raise HTTPException(400, "Enter a path, a GitHub URL or a pull request, or upload a file.")
        overrides = _scan_overrides(body)
        try:
            Settings.model_validate(_merge(load_settings().model_dump(mode="json"), overrides))
        except Exception as exc:
            raise HTTPException(400, f"Invalid settings: {exc}")
        ai = bool(body.get("ai", True))
        if ai:
            prov = ProviderName(overrides.get("llm", {}).get("provider", load_settings().llm.provider.value))
            if prov != ProviderName.OLLAMA and key_status(prov) == "not set":
                raise HTTPException(400, f"No API key for {prov.value}. Add it in Settings, or turn AI off.")
        rule_paths = [p.strip() for p in (body.get("rule_paths") or "").splitlines() if p.strip()]
        opts = ScanOptions(target=target, github_pr=pr, ref=(body.get("ref") or None), ai=ai,
                           rule_paths=rule_paths, overrides=overrides)
        run_id = jobs.start(opts)
        return {"run_id": run_id}

    @app.post("/api/runs/{run_id}/cancel")
    def api_cancel(run_id: str):
        return {"cancelled": jobs.cancel(run_id)}

    @app.post("/api/runs/{run_id}/findings/{fid}/answer")
    async def api_answer(run_id: str, fid: str, request: Request):
        body = await request.json()
        answer = (body.get("answer") or "").strip()
        if not answer:
            raise HTTPException(400, "Write an answer first.")
        try:
            f = await service.reverify_async(run_id, fid, answer)
        except KeyError as exc:
            raise HTTPException(404, str(exc))
        except Exception as exc:
            raise HTTPException(502, f"Re-verification failed: {exc}")
        run = load_run(run_id)
        from ..reports import write_reports

        write_reports(run, store.run_dir(run.id), run.settings.get("output", {}).get("formats", ["json", "txt"]))
        return f.model_dump(mode="json")

    @app.get("/api/runs/{run_id}/findings/{fid}/fix-preview")
    def api_fix_preview(run_id: str, fid: str):
        try:
            plan = plan_fix(load_run(run_id), fid)
        except FixError as exc:
            raise HTTPException(409, str(exc))
        return {"finding": plan.finding_id, "file": str(plan.file), "diff": plan.diff, "how": plan.how}

    @app.post("/api/runs/{run_id}/findings/{fid}/fix")
    async def api_fix(run_id: str, fid: str, request: Request):
        body = await request.json()
        try:
            plan = apply_fix(store, run_id, fid, confirm=str(body.get("confirm", "")), via="web")
        except FixError as exc:
            raise HTTPException(409, str(exc))
        return {"applied": True, "file": str(plan.file), "backup": str(plan.file) + ".argus-bak"}

    @app.get("/api/runs/{run_id}/report/{kind}")
    def api_report(run_id: str, kind: str):
        run = load_run(run_id)
        if kind == "json":
            return Response(json.dumps(to_json(run), indent=2), media_type="application/json",
                            headers={"Content-Disposition": f'attachment; filename="argus-{run.id}.json"'})
        if kind == "txt":
            return Response(to_text(run), media_type="text/plain; charset=utf-8",
                            headers={"Content-Disposition": f'attachment; filename="argus-{run.id}.txt"'})
        if kind == "sarif":
            return Response(json.dumps(to_sarif(run), indent=2), media_type="application/sarif+json",
                            headers={"Content-Disposition": f'attachment; filename="argus-{run.id}.sarif"'})
        if kind == "md":
            return Response(to_markdown(run), media_type="text/markdown; charset=utf-8",
                            headers={"Content-Disposition": f'attachment; filename="argus-{run.id}.md"'})
        raise HTTPException(404, "unknown report type")

    @app.get("/api/runs/{run_id}/patches/{fid}")
    def api_patch(run_id: str, fid: str):
        f = load_run(run_id).finding(fid)
        if f is None or not f.remediation.patch:
            raise HTTPException(404, "no patch for this finding")
        return Response(f.remediation.patch, media_type="text/x-diff",
                        headers={"Content-Disposition": f'attachment; filename="{f.id}.patch"'})

    @app.post("/api/runs/{run_id}/delete")
    def api_delete(run_id: str):
        load_run(run_id)
        store.delete(run_id)
        return {"deleted": True}

    # rules ------------------------------------------------------------------
    @app.get("/api/rules")
    def api_rules():
        rs = load_rules(load_settings())
        return {"rules": [r.summary() for r in rs.rules.values()], "errors": [str(e) for e in rs.errors]}

    @app.post("/api/rules/validate")
    async def api_rules_validate(request: Request):
        body = await request.json()
        try:
            raw = yaml.safe_load(body.get("yaml") or "")
        except yaml.YAMLError as exc:
            return {"ok": False, "errors": [f"YAML: {exc}"]}
        rules, errors = parse_rule_data(raw, "editor", "user")
        return {"ok": not errors and bool(rules), "rules": [r.summary() for r in rules],
                "errors": [str(e) for e in errors] or ([] if rules else ["No rules found."])}

    @app.post("/api/rules")
    async def api_rules_save(request: Request):
        """Save a custom rule from the form (dict) or the YAML editor (text)."""
        body = await request.json()
        if body.get("yaml"):
            try:
                raw = yaml.safe_load(body["yaml"])
            except yaml.YAMLError as exc:
                raise HTTPException(400, f"YAML: {exc}")
            rules, errors = parse_rule_data(raw, "editor", "user")
            if errors or not rules:
                raise HTTPException(400, "; ".join(str(e) for e in errors) or "No rules found.")
            name = _SAFE_NAME.sub("-", body.get("filename") or rules[0].id)[:80]
            path = user_rules_dir() / (name if name.endswith((".yaml", ".yml")) else name + ".yaml")
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(body["yaml"], encoding="utf-8")
            return {"saved": str(path), "rules": [r.id for r in rules]}
        rule = body.get("rule") or {}
        try:
            path = save_custom_rule(_clean_rule(rule))
        except ValueError as exc:
            raise HTTPException(400, str(exc))
        return {"saved": str(path), "rules": [rule.get("id")]}

    @app.post("/api/rules/{rule_id}/toggle")
    async def api_rule_toggle(rule_id: str, request: Request):
        body = await request.json()
        s = load_settings()
        disabled = set(s.rules.disable)
        if body.get("enabled"):
            disabled.discard(rule_id)
        else:
            disabled.add(rule_id)
        s.rules.disable = sorted(disabled)
        save_user_settings(s)
        return {"id": rule_id, "enabled": rule_id not in disabled}

    @app.post("/api/rules/{rule_id}/delete")
    def api_rule_delete(rule_id: str):
        rs = load_rules(load_settings())
        r = rs.get(rule_id)
        if r is None or r.origin != "user" or not r.source_file:
            raise HTTPException(400, "Only custom rules in your rules folder can be deleted here.")
        src = Path(r.source_file)
        others = [x for x in rs.rules.values() if x.source_file == r.source_file and x.id != rule_id]
        if others:
            raise HTTPException(400, f"{src.name} holds other rules too; edit the file to remove this one.")
        src.unlink(missing_ok=True)
        return {"deleted": rule_id}

    # settings -----------------------------------------------------------------
    @app.get("/api/settings")
    def api_settings():
        s = load_settings()
        return {"settings": s.model_dump(mode="json"), "keys": {p.value: key_status(p) for p in ProviderName}}

    @app.post("/api/settings")
    async def api_settings_save(request: Request):
        body = await request.json()
        current = load_settings().model_dump(mode="json")
        merged = _merge(current, body.get("settings") or {})
        try:
            s = Settings.model_validate(merged)
        except Exception as exc:
            raise HTTPException(400, f"Invalid settings: {exc}")
        save_user_settings(s)
        restart = s.server.port != load_settings().server.port
        return {"saved": True, "restart_needed": restart}

    @app.post("/api/settings/key")
    async def api_settings_key(request: Request):
        body = await request.json()
        try:
            where = set_api_key(ProviderName(body.get("provider")), body.get("key") or "")
        except ValueError as exc:
            raise HTTPException(400, str(exc))
        return {"stored_in": where}

    @app.get("/api/models")
    async def api_models(provider: str | None = None):
        from ..llm import create_provider

        s = load_settings()
        if provider:
            s.llm.provider = ProviderName(provider)
            s.llm.base_url = None
        p = create_provider(s.llm)
        try:
            return {"models": await p.list_models()}
        except Exception as exc:
            raise HTTPException(502, f"Could not list models: {exc}")
        finally:
            await p.aclose()

    return app, token


# ----------------------------------------------------------------- helpers
def _short_target(target: str) -> str:
    """'/home/me/work/shop-api' -> 'work/shop-api'; URLs -> 'org/repo'."""
    t = (target or "").rstrip("/")
    m = re.match(r"^(?:https?://github\.com/|github:)([^/]+/[^/#]+)", t)
    if m:
        return m.group(1).removesuffix(".git")
    parts = [p for p in re.split(r"[\\/]", t) if p not in ("", ".", "..")]
    return "/".join(parts[-2:]) if parts else t


def _merge(base: dict, override: dict) -> dict:
    out = dict(base)
    for k, v in override.items():
        out[k] = _merge(out[k], v) if isinstance(v, dict) and isinstance(out.get(k), dict) else v
    return out


def _scan_overrides(body: dict) -> dict:
    o: dict = {"llm": {}, "scan": {}}
    if body.get("provider"):
        o["llm"]["provider"] = body["provider"]
        o["llm"]["model"] = body.get("model") or DEFAULT_MODELS[ProviderName(body["provider"])]
    elif body.get("model"):
        o["llm"]["model"] = body["model"]
    for key in ("votes", "owasp_edition", "min_severity", "mode", "hunters"):
        if body.get(key) not in (None, ""):
            o["scan"][key] = int(body[key]) if key == "votes" else body[key]
    if isinstance(body.get("categories"), list):
        o["scan"]["categories"] = body["categories"]
    if body.get("trace") is not None:
        o["scan"]["trace"] = bool(body["trace"])
    if body.get("languages"):
        o["scan"]["languages"] = body["languages"]
    return {k: v for k, v in o.items() if v}


def _save_upload(upload: dict) -> str:
    """Single-file upload from the browser (text sent as JSON). Stored under
    the data dir, never inside a project."""
    name = _SAFE_NAME.sub("_", Path(str(upload.get("name", "upload.txt"))).name)[:120] or "upload"
    if Path(name).suffix.lower() not in _ALLOWED_UPLOAD:
        raise HTTPException(400, "Upload a .java, .py or .js file.")
    content = str(upload.get("content", ""))
    if len(content.encode("utf-8", "replace")) > 2_000_000:
        raise HTTPException(400, "Uploads are limited to 2 MB; scan the folder instead.")
    folder = data_dir() / "uploads" / secrets.token_hex(6)
    folder.mkdir(parents=True, exist_ok=True)
    path = folder / name
    path.write_text(content, encoding="utf-8")
    # Keep only the 20 most recent uploads.
    ups = sorted((data_dir() / "uploads").iterdir(), key=lambda p: p.stat().st_mtime, reverse=True)
    for old in ups[20:]:
        shutil.rmtree(old, ignore_errors=True)
    return str(path)


def _clean_rule(rule: dict) -> dict:
    """Form fields -> rule dict (textareas become lists, blanks dropped)."""
    out = {}
    for k, v in rule.items():
        if k in ("patterns", "pattern-not", "references", "include", "exclude") and isinstance(v, str):
            v = [x.strip() for x in v.splitlines() if x.strip()]
        if v in ("", None, []):
            continue
        out[k] = v
    return out


_LOCKED_PAGE = """<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Argus: locked</title>
<link rel="stylesheet" href="/static/style.css"></head><body class="locked"><main class="locked-box">
<h1>Argus is locked</h1><p>Open the link that <code>argus serve</code> printed in your terminal.
It contains a one-time access token, and it changes every time the server restarts.</p></main></body></html>"""
