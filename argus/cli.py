"""Command-line interface (`argus ...`).

Everything the web UI can do is available here too, and both call the same
ScanService / fixer / rules modules, so behaviour is identical.

    argus init                         first-time setup: UI port, LLM provider, model, key
    argus scan <file|dir|github-url>   run a scan -> findings.json + report.txt (+ SARIF)
    argus serve                        start the localhost web UI on the configured port
    argus findings list|show           browse results in the terminal
    argus context answer|note          answer "needs context" questions
    argus fix <ID>                     review and apply ONE fix (asks for consent)
    argus rules list|new|validate|test|enable|disable   manage detection rules
    argus config show|set|path         view or change settings
    argus models                       list models available for the provider
    argus baseline create              accept current findings (CI only fails on new ones)
    argus bench consistency            measure run-to-run stability
"""

from __future__ import annotations

import asyncio
import json
import socket
import sys
import threading
from pathlib import Path
from typing import Optional

import typer
import yaml
from rich.console import Console
from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.syntax import Syntax
from rich.table import Table

from . import __version__
from .config import (
    DEFAULT_BASE_URLS,
    DEFAULT_MODELS,
    SEVERITY_ORDER,
    ProviderName,
    load_settings,
    save_user_settings,
    set_config_value,
    user_config_path,
    user_rules_dir,
)
from .credentials import ENV_VARS, key_status, set_api_key

app = typer.Typer(add_completion=False, no_args_is_help=True, help="Argus: AI-agent SAST for Java, Python and JavaScript.")
config_app = typer.Typer(no_args_is_help=True, help="View or change settings.")
rules_app = typer.Typer(no_args_is_help=True, help="Manage built-in and custom detection rules.")
findings_app = typer.Typer(no_args_is_help=True, help="Browse findings of a scan.")
context_app = typer.Typer(no_args_is_help=True, help="Give Argus context it cannot see in the code.")
baseline_app = typer.Typer(no_args_is_help=True, help="Accept existing findings so CI fails only on new ones.")
bench_app = typer.Typer(no_args_is_help=True, help="Quality measurements.")
app.add_typer(config_app, name="config")
app.add_typer(rules_app, name="rules")
app.add_typer(findings_app, name="findings")
app.add_typer(context_app, name="context")
app.add_typer(baseline_app, name="baseline")
app.add_typer(bench_app, name="bench")

console = Console()
err = Console(stderr=True)
SEV_STYLE = {"critical": "bold white on red", "high": "bold red", "medium": "yellow", "low": "cyan", "info": "dim"}


def _version(value: bool) -> None:
    if value:
        console.print(f"argus {__version__}")
        raise typer.Exit()


@app.callback()
def _root(version: bool = typer.Option(False, "--version", callback=_version, is_eager=True, help="Show version.")) -> None:
    pass


def _store():
    from .store import RunStore

    return RunStore()


def _port_free(host: str, port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.bind((host, port))
            return True
        except OSError:
            return False


# =============================================================== init
@app.command()
def init(
    port: Optional[int] = typer.Option(None, help="Port for the localhost web UI (1024-65535)."),
    provider: Optional[ProviderName] = typer.Option(None, help="LLM provider: anthropic, openai, xai or ollama."),
    model: Optional[str] = typer.Option(None, help="Model name for that provider."),
    api_key: Optional[str] = typer.Option(None, help="API key (stored in the OS keyring, never in config)."),
    base_url: Optional[str] = typer.Option(None, help="Override the provider URL (e.g. a remote Ollama host)."),
    yes: bool = typer.Option(False, "--yes", "-y", help="Non-interactive: accept defaults for anything not given."),
) -> None:
    """First-time setup: choose the UI port and your LLM."""
    settings = load_settings()
    console.print(Panel.fit("[bold]Argus setup[/bold]\nAnswers are saved to " + str(user_config_path())))

    # 1. Port for the web UI -------------------------------------------------
    while True:
        p = port if port is not None else (settings.server.port if yes else
                                             typer.prompt("Port for the web UI", default=settings.server.port, type=int))
        if not 1024 <= p <= 65535:
            err.print("[red]Port must be between 1024 and 65535.[/red]")
        elif not _port_free(settings.server.host, p) and p != settings.server.port:
            err.print(f"[red]Port {p} is in use; pick another.[/red]")
        else:
            break
        if port is not None or yes:
            raise typer.Exit(2)
    settings.server.port = p

    # 2. Provider (closed list) ----------------------------------------------
    if provider is None and not yes:
        choices = ", ".join(x.value for x in ProviderName)
        while True:
            raw = typer.prompt(f"LLM provider ({choices})", default=settings.llm.provider.value)
            try:
                provider = ProviderName(raw.strip().lower())
                break
            except ValueError:
                err.print(f"[red]Unsupported provider {raw!r}. Argus supports only: {choices}.[/red]")
    provider = provider or settings.llm.provider
    if provider != settings.llm.provider:
        settings.llm.model = DEFAULT_MODELS[provider]
        settings.llm.base_url = None
    settings.llm.provider = provider

    # 3. Model + endpoint ------------------------------------------------------
    settings.llm.model = model or (settings.llm.model if yes else
                                   typer.prompt("Model", default=settings.llm.model or DEFAULT_MODELS[provider]))
    if base_url is not None:
        settings.llm.base_url = base_url or None
    elif provider == ProviderName.OLLAMA and not yes:
        settings.llm.base_url = typer.prompt("Ollama URL", default=settings.llm.base_url or DEFAULT_BASE_URLS[provider])

    # 4. API key -------------------------------------------------------------
    if provider != ProviderName.OLLAMA:
        key = api_key
        if key is None and not yes and key_status(provider) == "not set":
            key = typer.prompt(f"{provider.value} API key (input hidden; Enter to use ${ENV_VARS[provider]} instead)",
                               default="", hide_input=True, show_default=False)
        if key:
            where = set_api_key(provider, key)
            console.print(f"API key stored in {where}.")
        console.print(f"API key: {key_status(provider)}")

    path = save_user_settings(settings)
    console.print(f"[green]Saved[/green] {path}")
    console.print(f"Next: [bold]argus serve[/bold] (web UI on http://127.0.0.1:{settings.server.port}) "
                  f"or [bold]argus scan ./your-project[/bold]")


# =============================================================== scan
def _overrides(provider, model, votes, owasp, categories, min_severity, mode, no_trace, no_cache, max_calls,
               languages, formats, exclude) -> dict:
    o: dict = {"llm": {}, "scan": {}, "output": {}}
    if provider:
        o["llm"]["provider"] = provider.value
        o["llm"]["model"] = model or DEFAULT_MODELS[provider]
    if model:
        o["llm"]["model"] = model
    if votes is not None:
        o["scan"]["votes"] = votes
    if owasp:
        o["scan"]["owasp_edition"] = owasp
    if categories:
        o["scan"]["categories"] = [c.strip() for c in categories.split(",") if c.strip()]
    if min_severity:
        o["scan"]["min_severity"] = min_severity
    if mode:
        o["scan"]["mode"] = mode
    if no_trace:
        o["scan"]["trace"] = False
    if no_cache:
        o["scan"]["use_cache"] = False
    if max_calls:
        o["scan"]["max_llm_calls"] = max_calls
    if languages:
        o["scan"]["languages"] = [x.strip() for x in languages.split(",") if x.strip()]
    if exclude:
        o["scan"]["exclude"] = load_settings().scan.exclude + list(exclude)
    if formats:
        o["output"]["formats"] = [x.strip() for x in formats.split(",") if x.strip()]
    return {k: v for k, v in o.items() if v}


@app.command()
def scan(
    target: Optional[str] = typer.Argument(None, help="File, folder, or GitHub URL (https://github.com/org/repo)."),
    github_pr: Optional[str] = typer.Option(None, "--github-pr", help="Scan a PR's changed files: owner/repo#123."),
    ref: Optional[str] = typer.Option(None, help="Branch or tag for a GitHub URL."),
    since: Optional[str] = typer.Option(None, help="Only files changed since this git ref (local repos)."),
    provider: Optional[ProviderName] = typer.Option(None, help="Override the LLM provider for this run."),
    model: Optional[str] = typer.Option(None, help="Override the model for this run."),
    no_ai: bool = typer.Option(False, "--no-ai", help="Rules only: no LLM calls, nothing leaves the machine."),
    rules: list[str] = typer.Option([], "--rules", "-r", help="Extra rule file or folder (repeatable)."),
    votes: Optional[int] = typer.Option(None, help="Self-consistency runs per chunk (1-7, default 3)."),
    owasp: Optional[str] = typer.Option(None, help="OWASP edition for reports: 2025 or 2021."),
    categories: Optional[str] = typer.Option(None, help="Only these OWASP categories, e.g. A01,A05."),
    min_severity: Optional[str] = typer.Option(None, help="Hide findings below: info|low|medium|high|critical."),
    mode: Optional[str] = typer.Option(None, help="full (every chunk) or focused (chunks with rule signals)."),
    languages: Optional[str] = typer.Option(None, help="Subset of java,python,javascript."),
    exclude: list[str] = typer.Option([], "--exclude", "-x", help="Extra glob to exclude (repeatable)."),
    no_trace: bool = typer.Option(False, "--no-trace", help="Skip the Tracer agent (fewer LLM calls)."),
    no_cache: bool = typer.Option(False, "--no-cache", help="Ignore the LLM response cache."),
    max_llm_calls: Optional[int] = typer.Option(None, help="Hard cap on LLM calls for this run."),
    baseline: Optional[str] = typer.Option(None, help="Baseline file (default: <target>/.argus-baseline.json)."),
    out: str = typer.Option(None, "--out", "-o", help="Folder for reports (default from config: argus-results)."),
    formats: Optional[str] = typer.Option(None, "--format", "-f", help="json,txt,sarif,md (json and txt are always written)."),
    fail_on: Optional[str] = typer.Option(None, help="Exit 1 if any finding is at/above this severity (CI)."),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Only print the summary."),
) -> None:
    """Scan code and write findings.json + report.txt (and SARIF if configured)."""
    from .pipeline import ScanOptions, ScanService, fail_threshold_hit

    if fail_on and fail_on not in SEVERITY_ORDER:
        err.print(f"[red]--fail-on must be one of {SEVERITY_ORDER}[/red]")
        raise typer.Exit(2)
    try:
        overrides = _overrides(provider, model, votes, owasp, categories, min_severity, mode, no_trace, no_cache,
                               max_llm_calls, languages, formats, exclude)
        settings = load_settings(overrides)
    except Exception as exc:
        err.print(f"[red]Invalid settings:[/red] {exc}")
        raise typer.Exit(2)

    if not no_ai and settings.llm.provider != ProviderName.OLLAMA and key_status(settings.llm.provider) == "not set":
        err.print(f"[red]No API key for {settings.llm.provider.value}.[/red] Run `argus init`, set "
                  f"${ENV_VARS[settings.llm.provider]}, choose --provider ollama, or use --no-ai.")
        raise typer.Exit(3)

    out_dir = out or settings.output.dir
    opts = ScanOptions(target=target, ref=ref, github_pr=github_pr, since=since, ai=not no_ai,
                       rule_paths=list(rules), overrides=overrides, baseline=baseline, out_dir=out_dir)
    if not quiet:
        mode_s = "rules only" if no_ai else f"{settings.llm.provider.value}:{settings.llm.model}, votes {settings.scan.votes}"
        console.print(f"[bold]Argus[/bold] scanning [cyan]{target or github_pr}[/cyan] ({mode_s})")

    service = ScanService()
    with Progress(SpinnerColumn(), TextColumn("{task.description}"), BarColumn(), TextColumn("{task.percentage:>3.0f}%"),
                  TimeElapsedColumn(), console=err, transient=True, disable=quiet) as prog:
        task = prog.add_task("starting", total=1.0)

        def on_progress(event: str, data: dict) -> None:
            if event == "phase":
                desc = data["phase"]
                if "done" in data:
                    desc += f" ({data['done']}/{data['total']})"
                prog.update(task, completed=data["progress"], description=desc)

        try:
            run = service.run(opts, progress=on_progress)
        except KeyboardInterrupt:
            err.print("[yellow]Cancelled.[/yellow]")
            raise typer.Exit(130)

    for w in run.warnings[:10]:
        err.print(f"[yellow]warning:[/yellow] {w}")
    if run.status != "completed":
        for e in run.errors:
            err.print(f"[red]error:[/red] {e}")
        raise typer.Exit(2)

    _print_summary(run, quiet)
    dest = Path(out_dir) / run.id
    console.print(f"\nReports: [bold]{dest / 'findings.json'}[/bold]  [bold]{dest / 'report.txt'}[/bold]"
                  + (f"  [bold]{dest / 'findings.sarif'}[/bold]" if (dest / "findings.sarif").exists() else ""))
    console.print(f"Run id: {run.id}   (argus findings show <ID> · argus fix <ID> · argus serve)")
    if fail_threshold_hit(run, fail_on):
        raise typer.Exit(1)


def _print_summary(run, quiet: bool = False) -> None:
    c = run.counts()
    sev = "  ".join(f"[{SEV_STYLE[k]}]{k} {v}[/]" for k, v in c["by_severity"].items())
    console.print(f"\n[bold]{len(run.active_findings())} active findings[/bold]  {sev}")
    by_status = ", ".join(f"{k} {v}" for k, v in c["by_status"].items())
    if by_status:
        console.print(f"[dim]by status: {by_status}[/dim]")
    if quiet:
        return
    t = Table(show_lines=False, header_style="bold")
    for col in ("ID", "Severity", "Status", "CWE", "OWASP", "Location", "Title"):
        t.add_column(col, overflow="fold")
    for f in run.active_findings():
        cat = f.owasp.get(run.owasp_edition) or "-"
        t.add_row(f.id, f"[{SEV_STYLE[f.severity]}]{f.severity}[/]", f.status, f.cwe or "-", cat,
                  f"{f.file}:{f.start_line}", f.title)
    if run.active_findings():
        console.print(t)
    nc = [f for f in run.findings if f.status == "needs_context"]
    if nc:
        console.print("\n[bold yellow]Argus needs your input on these lines:[/bold yellow]")
        for f in nc:
            console.print(f"  {f.id} {f.file}:{f.start_line}  {f.context_question}")
        console.print('  Answer with: argus context answer <ID> "<answer>"')


# =============================================================== serve
@app.command()
def serve(
    port: Optional[int] = typer.Option(None, help="Override the configured port."),
    host: Optional[str] = typer.Option(None, help="Bind address (default 127.0.0.1)."),
    allow_remote: bool = typer.Option(False, "--allow-remote", help="Allow binding to a non-loopback address."),
    open_browser: bool = typer.Option(False, "--open", help="Open the UI in your browser."),
) -> None:
    """Start the web UI on localhost (the port chosen in `argus init`)."""
    import uvicorn

    from .web.app import create_app

    settings = load_settings()
    host = host or settings.server.host
    port = port or settings.server.port
    loopback = host in ("127.0.0.1", "localhost", "::1")
    if not loopback and not (allow_remote or settings.server.allow_remote):
        err.print("[red]Refusing to bind to a non-loopback address without --allow-remote.[/red]")
        raise typer.Exit(2)
    if not loopback:
        err.print("[yellow]WARNING: the UI will be reachable from other machines. Anyone with the "
                  "access token can scan code and apply fixes.[/yellow]")
    web_app, token = create_app(host=host, port=port)
    url = f"http://{'127.0.0.1' if host in ('0.0.0.0', '::') else host}:{port}/?token={token}"
    console.print(Panel.fit(f"[bold]Argus web UI[/bold]\nOpen: [link={url}]{url}[/link]\n"
                            "The token in the link is required; it changes every time the server starts.\n"
                            "Press Ctrl+C to stop."))
    if open_browser:
        import webbrowser

        threading.Timer(1.0, lambda: webbrowser.open(url)).start()
    uvicorn.run(web_app, host=host, port=port, log_level="warning")


# =============================================================== findings
@findings_app.command("list")
def findings_list(
    run_id: str = typer.Option("latest", "--run", help="Run id (default: latest)."),
    severity: Optional[str] = typer.Option(None, help="Minimum severity."),
    status: Optional[str] = typer.Option(None, help="confirmed|needs_context|unverified|rejected|suppressed|all"),
    as_json: bool = typer.Option(False, "--json", help="Print JSON."),
) -> None:
    """List findings of a scan."""
    from .findings import severity_rank

    run = _load_run(run_id)
    items = run.findings if status == "all" else (
        [f for f in run.findings if f.status == status] if status else run.active_findings())
    if severity:
        items = [f for f in items if severity_rank(f.severity) >= severity_rank(severity)]
    if as_json:
        console.print_json(json.dumps([f.model_dump(mode="json") for f in items]))
        return
    t = Table(header_style="bold")
    for col in ("ID", "Severity", "Status", "Conf", "CWE", "Location", "Title"):
        t.add_column(col, overflow="fold")
    for f in items:
        t.add_row(f.id, f"[{SEV_STYLE[f.severity]}]{f.severity}[/]", f.status, f"{f.confidence:.2f}", f.cwe or "-",
                  f"{f.file}:{f.start_line}", f.title)
    console.print(t)
    console.print(f"[dim]run {run.id} · {run.target}[/dim]")


@findings_app.command("show")
def findings_show(finding_id: str, run_id: str = typer.Option("latest", "--run")) -> None:
    """Show one finding in full: code, data flow, explanation and fix."""
    from .reports import _finding_txt

    run = _load_run(run_id)
    f = run.finding(finding_id)
    if f is None:
        err.print(f"[red]{finding_id} not found in run {run.id}[/red]")
        raise typer.Exit(1)
    console.print(_finding_txt(f, run.owasp_edition), markup=False, highlight=False)


def _load_run(run_id: str):
    try:
        return _store().load(run_id)
    except FileNotFoundError as exc:
        err.print(f"[red]{exc}[/red]")
        raise typer.Exit(1)


# =============================================================== context
@context_app.command("answer")
def context_answer(
    finding_id: str,
    answer: str = typer.Argument(..., help="Your answer to the finding's question."),
    run_id: str = typer.Option("latest", "--run"),
    no_reverify: bool = typer.Option(False, "--no-reverify", help="Only store the answer."),
) -> None:
    """Answer a needs-context question; the finding is re-verified with your answer."""
    from .pipeline import ScanService
    from .store import ContextStore

    run = _load_run(run_id)
    f = run.finding(finding_id)
    if f is None:
        err.print(f"[red]{finding_id} not found in run {run.id}[/red]")
        raise typer.Exit(1)
    if no_reverify:
        ContextStore(run.target_key).set_answer(f.fingerprint, f.context_question, answer)
        console.print("Saved. It will be used on the next scan of this target.")
        return
    try:
        updated = ScanService().reverify(run.id, f.id, answer)
    except Exception as exc:
        err.print(f"[red]Re-verification failed:[/red] {exc}")
        raise typer.Exit(1)
    console.print(f"{updated.id}: [bold]{updated.status}[/bold] ({updated.severity}, confidence {updated.confidence:.2f})")
    if updated.status == "needs_context":
        console.print(f"Still needs context: {updated.context_question}")
    from .reports import write_reports

    run = _store().load(run.id)
    write_reports(run, _store().run_dir(run.id), run.settings.get("output", {}).get("formats", ["json", "txt"]))


@context_app.command("note")
def context_note(
    target: str = typer.Argument(..., help="The same target you scan (path or GitHub URL)."),
    notes: str = typer.Argument(..., help="Free-text context, e.g. 'Admin API is only reachable over VPN'."),
) -> None:
    """Store free-text context for a target; every agent sees it on future scans."""
    from .store import ContextStore

    p = Path(target)
    key = str(p.resolve()) if p.exists() else (target if target.startswith("http") else target)
    if target.startswith(("https://github.com/", "github:")):
        from .targets import _GITHUB_URL

        m = _GITHUB_URL.match(target)
        if m:
            key = f"https://github.com/{m.group(1)}/{m.group(2)}.git"
    elif p.exists():
        from .targets import _git, _is_git_repo

        root = p.resolve() if p.is_dir() else p.resolve().parent
        if _is_git_repo(root):
            remote = _git(["config", "--get", "remote.origin.url"], cwd=root, check=False).strip()
            key = remote or str(root)
        else:
            key = str(root)
    ContextStore(key).set_notes(notes)
    console.print(f"Saved context for {key}.")


# =============================================================== fix
@app.command()
def fix(
    finding_id: str,
    run_id: str = typer.Option("latest", "--run"),
    target_root: Optional[str] = typer.Option(None, help="Local checkout to patch (needed for GitHub scans)."),
    branch: bool = typer.Option(False, "--branch", help="Commit the fix on a new git branch argus/fix-<id>."),
    yes: bool = typer.Option(False, "--yes", help="Skip the prompt (scripts). Still applies ONLY this finding."),
) -> None:
    """Review and apply ONE suggested fix. Nothing changes without your consent."""
    from .fixer import FixError, apply_fix, plan_fix

    store = _store()
    run = _load_run(run_id)
    try:
        plan = plan_fix(run, finding_id, target_root)
    except FixError as exc:
        err.print(f"[red]Cannot fix:[/red] {exc}")
        raise typer.Exit(1)
    f = run.finding(plan.finding_id)
    console.print(Panel.fit(f"[bold]{f.id}[/bold] {f.title}\n{f.file}:{f.start_line} · {f.cwe} · {f.severity}\n\n"
                            f"{f.remediation.summary}"))
    console.print(Syntax(plan.diff, "diff", theme="ansi_dark", line_numbers=False))
    if plan.how == "relocated":
        console.print("[yellow]The file changed since the scan; the original lines were found and will be replaced.[/yellow]")
    if not yes:
        answer = typer.prompt(f"Apply this change to {plan.file}? Type the finding id ({f.id}) to confirm, or anything else to cancel",
                              default="", show_default=False)
        if answer.strip().upper() != f.id.upper():
            console.print("Cancelled. No files were changed.")
            raise typer.Exit(0)
    try:
        apply_fix(store, run.id, f.id, confirm=f.id, target_root=target_root, git_branch=branch, via="cli")
    except FixError as exc:
        err.print(f"[red]Not applied:[/red] {exc}")
        raise typer.Exit(1)
    console.print("[green]Applied.[/green] " + (f"Committed on branch argus/fix-{f.id.lower()}." if branch
                                                   else f"Backup: {plan.file}.argus-bak"))


# =============================================================== rules
@rules_app.command("list")
def rules_list(
    language: Optional[str] = typer.Option(None, "--lang", help="java|python|javascript"),
    custom_only: bool = typer.Option(False, "--custom", help="Only your custom rules."),
    rules: list[str] = typer.Option([], "--rules", "-r", help="Also load these rule files."),
) -> None:
    """List every rule Argus will use."""
    from .config import Language
    from .rules import load_rules

    rs = load_rules(load_settings(), rules)
    t = Table(header_style="bold")
    for col in ("ID", "Type", "Mode", "CWE", "Severity", "Languages", "Origin", "On"):
        t.add_column(col, overflow="fold")
    for r in sorted(rs.rules.values(), key=lambda r: (r.origin == "builtin", r.id)):
        if custom_only and r.origin == "builtin":
            continue
        if language and Language(language) not in r.languages:
            continue
        s = r.summary()
        t.add_row(s["id"], s["type"], s["mode"], s["cwe"] or "-", s["severity"] if r.type.value in ("pattern", "ai") else "-",
                  ",".join(s["languages"]), s["origin"], "yes" if r.enabled else "[dim]no[/dim]")
    console.print(t)
    console.print(f"[dim]Custom rules folder: {user_rules_dir()}[/dim]")
    for e in rs.errors:
        err.print(f"[red]rule error:[/red] {e}")


@rules_app.command("validate")
def rules_validate(paths: list[str] = typer.Argument(None, help="Rule files/folders (default: your custom rules).")) -> None:
    """Check rule files for errors (exit 1 if any)."""
    from .rules import parse_rule_file

    targets = [Path(p) for p in paths] if paths else [user_rules_dir()]
    files: list[Path] = []
    for p in targets:
        files += sorted([*p.glob("*.yaml"), *p.glob("*.yml")]) if p.is_dir() else [p]
    if not files:
        console.print("No rule files found.")
        return
    bad = 0
    for fp in files:
        if not fp.exists():
            err.print(f"[red]{fp}: not found[/red]")
            bad += 1
            continue
        rules, errors = parse_rule_file(fp, "user")
        for e in errors:
            err.print(f"[red]✗[/red] {e}")
        bad += len(errors)
        console.print(f"{'[green]✓[/green]' if not errors else '[red]✗[/red]'} {fp}: {len(rules)} valid rule(s)")
    if bad:
        raise typer.Exit(1)


@rules_app.command("new")
def rules_new(
    rule_id: str = typer.Argument(..., help="Unique id, e.g. acme.java.legacy-crypto"),
    rule_type: str = typer.Option("pattern", "--type", help="pattern | ai | source | sink | sanitizer"),
    language: list[str] = typer.Option([], "--lang", help="Language(s) the rule applies to (repeatable)."),
    out: Optional[str] = typer.Option(None, help="Write here instead of your custom rules folder."),
) -> None:
    """Create a commented starter rule file you can edit."""
    from .rules import SCAFFOLDS
    from .rules.loader import rule_to_yaml

    if rule_type not in SCAFFOLDS:
        err.print(f"[red]--type must be one of {list(SCAFFOLDS)}[/red]")
        raise typer.Exit(2)
    data = dict(SCAFFOLDS[rule_type])
    data["id"] = rule_id
    if language:
        data["languages"] = list(language)
    path = Path(out) if out else user_rules_dir() / f"{rule_id}.yaml"
    if path.exists():
        err.print(f"[red]{path} already exists[/red]")
        raise typer.Exit(1)
    path.parent.mkdir(parents=True, exist_ok=True)
    header = (
        "# Argus custom rule. Edit, then check with: argus rules validate " + str(path) + "\n"
        "# Fields: see README.md -> 'Custom rules'. Regexes use Python syntax; single-quote them in YAML.\n"
    )
    path.write_text(header + rule_to_yaml(data), encoding="utf-8")
    from .rules import parse_rule_file

    _, errors = parse_rule_file(path, "user")
    console.print(f"[green]Created[/green] {path}" + ("" if not errors else f" [red](edit needed: {errors[0].message})[/red]"))


@rules_app.command("test")
def rules_test(
    rule_file: str = typer.Argument(..., help="Rule file to test."),
    target: str = typer.Argument(..., help="File or folder to run it against."),
) -> None:
    """Run ONLY the rules in a file against code and show every match (no AI)."""
    from .index import CodeIndex
    from .rules import RuleEngine, parse_rule_file
    from .rules.loader import RuleSet
    from .targets import TargetError, resolve_target

    rules, errors = parse_rule_file(Path(rule_file), "cli")
    for e in errors:
        err.print(f"[red]✗[/red] {e}")
    if not rules:
        raise typer.Exit(1)
    rs = RuleSet(rules={r.id: r for r in rules})
    try:
        tgt = resolve_target(target, load_settings())
    except TargetError as exc:
        err.print(f"[red]{exc}[/red]")
        raise typer.Exit(1)
    eng = RuleEngine(rs)
    total = 0
    for fi in CodeIndex(tgt.files, redact=False).files.values():
        for s in eng.scan_file(fi.rel_path, fi.source.language, fi.lines):
            total += 1
            console.print(f"{fi.rel_path}:{s.line}  [bold]{s.rule_id}[/bold] ({s.rule_type}/{s.mode})  {s.text[:120]}",
                          highlight=False)
    tgt.cleanup()
    ai_rules = [r.id for r in rules if r.type.value == "ai"]
    if ai_rules:
        console.print(f"[dim]AI rules are not regex-based and only run during `argus scan`: {', '.join(ai_rules)}[/dim]")
    console.print(f"{total} match(es) from {len(rules)} rule(s).")


def _toggle_rule(rule_id: str, enable: bool) -> None:
    settings = load_settings()
    disabled = set(settings.rules.disable)
    (disabled.discard if enable else disabled.add)(rule_id)
    settings.rules.disable = sorted(disabled)
    save_user_settings(settings)
    console.print(f"{rule_id} {'enabled' if enable else 'disabled'}.")


@rules_app.command("disable")
def rules_disable(rule_id: str) -> None:
    """Switch a rule off (built-in or custom)."""
    _toggle_rule(rule_id, False)


@rules_app.command("enable")
def rules_enable(rule_id: str) -> None:
    """Switch a disabled rule back on."""
    _toggle_rule(rule_id, True)


# =============================================================== config / models
@config_app.command("show")
def config_show() -> None:
    """Print the effective settings (API keys are never shown)."""
    s = load_settings()
    data = s.model_dump(mode="json")
    console.print(Syntax(yaml.safe_dump(data, sort_keys=False), "yaml", theme="ansi_dark"))
    console.print(f"API key for {s.llm.provider.value}: {key_status(s.llm.provider)}")
    console.print(f"[dim]Config file: {user_config_path()}[/dim]")


@config_app.command("set")
def config_set(key: str = typer.Argument(..., help="e.g. llm.provider, scan.votes, server.port"),
               value: str = typer.Argument(...)) -> None:
    """Change one setting, e.g. `argus config set llm.provider ollama`."""
    try:
        s = set_config_value(key, value)
    except (KeyError, ValueError) as exc:
        err.print(f"[red]{exc}[/red]")
        raise typer.Exit(2)
    console.print(f"{key} = {value}")
    if key == "llm.provider":
        console.print(f"model reset to {s.llm.model} (change with `argus config set llm.model <name>`)")


@config_app.command("path")
def config_path() -> None:
    """Show where config, custom rules and data live."""
    from .config import data_dir

    console.print(f"config : {user_config_path()}\nrules  : {user_rules_dir()}\ndata   : {data_dir()}")


@config_app.command("set-key")
def config_set_key(provider: ProviderName) -> None:
    """Store an API key in the OS keyring (prompted, hidden)."""
    key = typer.prompt(f"{provider.value} API key", hide_input=True)
    console.print(f"Stored in {set_api_key(provider, key)}.")


@app.command()
def models(provider: Optional[ProviderName] = typer.Option(None, help="Provider (default: configured).")) -> None:
    """List models your key (or local Ollama) can use."""
    from .llm import create_provider

    s = load_settings()
    if provider:
        s.llm.provider = provider
        s.llm.base_url = None
    p = create_provider(s.llm)

    async def go():
        try:
            return await p.list_models()
        finally:
            await p.aclose()

    try:
        names = asyncio.run(go())
    except Exception as exc:
        err.print(f"[red]Could not list models:[/red] {exc}")
        raise typer.Exit(1)
    for n in names:
        console.print(n)


# =============================================================== baseline / cache / bench
@baseline_app.command("create")
def baseline_create(run_id: str = typer.Option("latest", "--run"),
                    out: str = typer.Option(".argus-baseline.json", help="Where to write the baseline.")) -> None:
    """Accept all active findings of a run; they will be marked suppressed next time."""
    from .store import write_baseline

    run = _load_run(run_id)
    n = write_baseline(run, Path(out))
    console.print(f"Baseline with {n} finding(s) written to {out}. Commit it to the repo root.")


@app.command("cache-clear")
def cache_clear() -> None:
    """Delete cached LLM responses."""
    from .config import data_dir
    from .llm import ResponseCache

    n = ResponseCache(data_dir() / "cache.sqlite").clear()
    console.print(f"Removed {n} cached response(s).")


@bench_app.command("consistency")
def bench_consistency(
    target: str,
    runs: int = typer.Option(3, help="How many scans to compare."),
    no_cache: bool = typer.Option(True, help="Disable the cache so the model is really re-asked."),
) -> None:
    """Scan the same code N times and report how similar the results are (Jaccard)."""
    from .pipeline import ScanOptions, ScanService

    sets = []
    for i in range(runs):
        r = ScanService().run(ScanOptions(target=target, overrides={"scan": {"use_cache": not no_cache}}))
        fps = {f.fingerprint for f in r.active_findings()}
        sets.append(fps)
        console.print(f"run {i + 1}: {len(fps)} active findings ({r.id})")
    pairs = [(a, b) for i, a in enumerate(sets) for b in sets[i + 1:]]
    scores = [len(a & b) / len(a | b) if (a | b) else 1.0 for a, b in pairs]
    console.print(f"[bold]Mean Jaccard similarity: {sum(scores) / len(scores):.3f}[/bold]" if scores else "need >= 2 runs")


@app.command("runs")
def runs_list() -> None:
    """List previous scans."""
    t = Table(header_style="bold")
    for col in ("Run", "When", "Status", "Target", "Model", "Active findings"):
        t.add_column(col, overflow="fold")
    for r in _store().list():
        active = sum(r["counts"]["by_severity"].values())
        t.add_row(r["id"], r["created_at"], r["status"], r["target"], f"{r['provider']}:{r['model']}" if r["ai_enabled"] else "rules only", str(active))
    console.print(t)


def main() -> None:
    try:
        app()
    except KeyboardInterrupt:  # pragma: no cover
        sys.exit(130)


if __name__ == "__main__":  # pragma: no cover
    main()
