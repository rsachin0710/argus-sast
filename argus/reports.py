"""Report writers: JSON (the machine contract), TXT (for humans), SARIF 2.1.0
(GitHub code scanning / IDEs) and Markdown (for sharing).

``write_reports`` writes every requested format into the run folder and,
optionally, copies them to the user's output folder. Patches are written one
per finding into patches/ — they are suggestions and are never applied here.
"""

from __future__ import annotations

import json
import shutil
import textwrap
from pathlib import Path

from . import __version__
from .findings import ACTIVE_STATUSES, Finding, ScanRun
from .taxonomy import OWASP_2021_NAMES, OWASP_2025_NAMES, owasp_label

REPORT_SCHEMA_VERSION = "1.0"


# --------------------------------------------------------------------- JSON
def to_json(run: ScanRun) -> dict:
    data = run.model_dump(mode="json")
    data.pop("settings", None)  # verbose; still kept in run.json
    return {
        "schema_version": REPORT_SCHEMA_VERSION,
        "tool": {"name": "argus-sast", "version": __version__},
        "run": {k: v for k, v in data.items() if k != "findings"},
        "summary": run.counts(),
        "findings": data["findings"],
    }


# ---------------------------------------------------------------------- TXT
def _wrap(text: str, indent: str = "    ", width: int = 100) -> str:
    out = []
    for para in (text or "").splitlines() or [""]:
        if not para.strip():
            out.append("")
            continue
        out.append(textwrap.fill(para, width=width, initial_indent=indent, subsequent_indent=indent))
    return "\n".join(out)


def _finding_txt(f: Finding, edition: str) -> str:
    owasp = owasp_label(f.owasp.get(edition), edition)
    lines = [
        f"[{f.severity.upper()}] {f.id}  {f.title}",
        f"  Status     : {f.status}" + (f" (confidence {f.confidence:.2f}, votes {f.votes})" if f.votes else f" (confidence {f.confidence:.2f})"),
        f"  Location   : {f.file}:{f.start_line}" + (f"-{f.end_line}" if f.end_line != f.start_line else "") + (f"  in {f.function}" if f.function else ""),
        f"  Weakness   : {f.cwe} {f.cwe_name}",
        f"  OWASP      : {owasp}",
        f"  Detected by: {f.detector}" + (f" (rule {f.rule_id})" if f.rule_id else ""),
        "",
        "  Code:",
    ]
    if f.code_context:
        rel = f.start_line - f.code_context.start_line
        lo, hi = max(0, rel - 3), min(len(f.code_context.lines), rel + 4)
        for i in range(lo, hi):
            n = f.code_context.start_line + i
            mark = ">>" if f.start_line <= n <= f.end_line else "  "
            lines.append(f"    {mark} {n:5} | {f.code_context.lines[i]}")
    else:
        lines.append(f"    >> {f.start_line:5} | {f.snippet}")
    if f.data_flow:
        lines += ["", "  Data flow:"]
        lines += [f"    {s.role:<11} {s.file}:{s.line}  {s.note}" for s in f.data_flow]
    lines += ["", "  Why it is flagged:", _wrap(f.explanation or "(no explanation)")]
    if f.exploit_scenario:
        lines += ["", "  Exploit scenario:", _wrap(f.exploit_scenario)]
    if f.impact:
        lines += ["", "  Impact:", _wrap(f.impact)]
    if f.status == "needs_context" and f.context_question:
        lines += ["", "  NEEDS YOUR INPUT:", _wrap(f.context_question),
                  f"    Answer with: argus context answer {f.id} \"<your answer>\""]
    if f.context_answer:
        lines += ["", "  Your context answer:", _wrap(f.context_answer)]
    r = f.remediation
    if r.summary or r.patch or r.fixed_code:
        lines += ["", "  Remediation:", _wrap(r.summary or "")]
        if r.patch:
            lines += ["", "  Suggested patch (NOT applied; run `argus fix " + f.id + "` to review and apply):"]
            lines += ["    " + ln for ln in r.patch.rstrip("\n").splitlines()]
        elif r.fixed_code:
            lines += ["", f"  Suggested secure code for lines {r.start_line}-{r.end_line} ({r.validation_note}):"]
            lines += ["    " + ln for ln in r.fixed_code.splitlines()]
    if f.references:
        lines += ["", "  References: " + ", ".join(f.references[:4])]
    return "\n".join(lines)


def to_text(run: ScanRun) -> str:
    edition = run.owasp_edition
    c = run.counts()
    head = [
        "=" * 100,
        f"Argus SAST report  ·  run {run.id}  ·  {run.created_at}",
        "=" * 100,
        f"Target        : {run.target} ({run.target_kind})",
        f"Mode          : {'AI agents (' + str(run.provider) + ':' + str(run.model) + ')' if run.ai_enabled else 'rules only (no AI)'}",
        f"Files scanned : {run.stats.files_scanned} ({run.stats.lines_scanned} lines), skipped {run.stats.files_skipped}",
        f"Rules         : {run.stats.rules_loaded} active, {run.stats.custom_rules} custom",
    ]
    if run.ai_enabled:
        head.append(
            f"LLM calls     : {run.stats.llm_calls} (+{run.stats.llm_cache_hits} cached), "
            f"tokens in/out {run.stats.input_tokens}/{run.stats.output_tokens}, "
            f"votes {run.settings.get('scan', {}).get('votes', '?')}"
        )
    head.append(f"Duration      : {run.stats.duration_seconds}s   Status: {run.status}")
    head += ["", "Summary (active findings by severity): " + ", ".join(f"{k} {v}" for k, v in c["by_severity"].items()),
             "By status: " + (", ".join(f"{k} {v}" for k, v in c["by_status"].items()) or "none")]
    if run.errors:
        head += ["", "ERRORS:"] + [f"  - {e}" for e in run.errors]
    if run.warnings:
        head += ["", "Warnings:"] + [f"  - {w}" for w in run.warnings[:20]]

    active = [f for f in run.findings if f.status in ACTIVE_STATUSES]
    body = []
    if active:
        body += ["", "-" * 100, "FINDINGS", "-" * 100]
        for f in active:
            body += ["", _finding_txt(f, edition), "", "-" * 100]
    else:
        body += ["", "No active findings."]
    other = [f for f in run.findings if f.status not in ACTIVE_STATUSES]
    if other:
        body += ["", "Not reported (rejected by the Verifier or suppressed):"]
        body += [f"  {f.id} {f.status:<10} {f.file}:{f.start_line} {f.cwe} {f.title}"
                 + (f" ({f.suppressed_reason})" if f.suppressed_reason else "") for f in other]
    if run.signals_not_flagged:
        body += ["", "Dangerous sinks the agents did not flag (review if in doubt):"]
        body += [f"  {s['file']}:{s['line']} {s.get('cwe') or ''} [{s['rule_id']}] {s['text'][:90]}"
                 for s in run.signals_not_flagged[:40]]
    return "\n".join(head + body) + "\n"


# -------------------------------------------------------------------- SARIF
_SARIF_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}
_SECURITY_SEVERITY = {"critical": "9.5", "high": "8.0", "medium": "5.5", "low": "3.0", "info": "1.0"}


def to_sarif(run: ScanRun) -> dict:
    rules: dict[str, dict] = {}
    results = []
    for f in run.findings:
        if f.status not in ACTIVE_STATUSES:
            continue
        rule_id = f.rule_id or (f.cwe or "argus.ai")
        if rule_id not in rules:
            tags = ["security"]
            if f.cwe:
                tags.append(f"external/cwe/{f.cwe.lower()}")
            if f.owasp.get("2025"):
                tags.append(f"owasp-2025/{f.owasp['2025']}")
            rules[rule_id] = {
                "id": rule_id,
                "name": rule_id.replace(".", "_").replace("-", "_"),
                "shortDescription": {"text": f.cwe_name or f.title},
                "helpUri": f.references[0] if f.references else "https://owasp.org/Top10/",
                "properties": {"tags": tags, "security-severity": _SECURITY_SEVERITY[f.severity]},
            }
        msg = f"{f.title}. {f.explanation}".strip()
        if f.status == "needs_context" and f.context_question:
            msg += f"\n\nNeeds context: {f.context_question}"
        result = {
            "ruleId": rule_id,
            "level": _SARIF_LEVEL[f.severity],
            "message": {"text": msg[:4000]},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": f.file},
                    "region": {"startLine": f.start_line, "endLine": f.end_line},
                }
            }],
            "partialFingerprints": {"argusFingerprint/v1": f.fingerprint},
            "properties": {"argusId": f.id, "status": f.status, "confidence": f.confidence,
                           "severity": f.severity, "cwe": f.cwe, "owasp": f.owasp},
        }
        if f.data_flow:
            result["codeFlows"] = [{"threadFlows": [{"locations": [
                {"location": {"physicalLocation": {"artifactLocation": {"uri": s.file}, "region": {"startLine": s.line}},
                              "message": {"text": f"{s.role}: {s.note}"[:500]}}}
                for s in f.data_flow
            ]}]}]
        results.append(result)
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "Argus", "version": __version__, "informationUri": "https://github.com/argus-sast/argus",
                                "rules": list(rules.values())}},
            "results": results,
            "automationDetails": {"id": f"argus/{run.id}"},
        }],
    }


# ----------------------------------------------------------------- Markdown
def to_markdown(run: ScanRun) -> str:
    edition = run.owasp_edition
    names = OWASP_2025_NAMES if edition == "2025" else OWASP_2021_NAMES
    c = run.counts()
    out = [f"# Argus report: {run.target}", "",
           f"Run `{run.id}` · {run.created_at} · " + (f"AI: `{run.provider}:{run.model}`" if run.ai_enabled else "rules only"), "",
           "| Severity | Count |", "| --- | --- |"]
    out += [f"| {k} | {v} |" for k, v in c["by_severity"].items()]
    out += ["", "| ID | Severity | Status | CWE | OWASP | Location | Title |", "| --- | --- | --- | --- | --- | --- | --- |"]
    for f in run.active_findings():
        cat = f.owasp.get(edition)
        out.append(f"| {f.id} | {f.severity} | {f.status} | {f.cwe} | {cat + ' ' + names[cat] if cat else '-'} | "
                   f"`{f.file}:{f.start_line}` | {f.title} |")
    for f in run.active_findings():
        out += ["", f"## {f.id} · {f.title}", "",
                f"**{f.severity.upper()}** · {f.status} · {f.cwe} {f.cwe_name} · `{f.file}:{f.start_line}`", "",
                f.explanation or ""]
        if f.context_question and f.status == "needs_context":
            out += ["", f"> **Needs context:** {f.context_question}"]
        if f.remediation.patch:
            out += ["", "```diff", f.remediation.patch.rstrip("\n"), "```"]
        elif f.remediation.summary:
            out += ["", f"**Fix:** {f.remediation.summary}"]
    return "\n".join(out) + "\n"


# ------------------------------------------------------------------- writer
def write_reports(run: ScanRun, run_dir: Path, formats: list[str], out_dir: Path | None = None) -> dict[str, Path]:
    run_dir.mkdir(parents=True, exist_ok=True)
    written: dict[str, Path] = {}
    if "json" in formats:
        p = run_dir / "findings.json"
        p.write_text(json.dumps(to_json(run), indent=2), encoding="utf-8")
        written["json"] = p
    if "txt" in formats:
        p = run_dir / "report.txt"
        p.write_text(to_text(run), encoding="utf-8")
        written["txt"] = p
    if "sarif" in formats:
        p = run_dir / "findings.sarif"
        p.write_text(json.dumps(to_sarif(run), indent=2), encoding="utf-8")
        written["sarif"] = p
    if "md" in formats:
        p = run_dir / "report.md"
        p.write_text(to_markdown(run), encoding="utf-8")
        written["md"] = p
    patches = run_dir / "patches"
    for f in run.findings:
        if f.remediation.patch:
            patches.mkdir(exist_ok=True)
            (patches / f"{f.id}.patch").write_text(f.remediation.patch, encoding="utf-8")
    if out_dir is not None:
        dest = out_dir / run.id
        dest.mkdir(parents=True, exist_ok=True)
        for kind, p in list(written.items()):
            shutil.copy2(p, dest / p.name)
            written[kind] = dest / p.name
        if patches.is_dir():
            shutil.copytree(patches, dest / "patches", dirs_exist_ok=True)
    return written
