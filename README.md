# Argus

**Open-source, AI-agent powered static application security testing (SAST) for Java, Python and JavaScript.**

Argus reads your code, uses a team of LLM agents to find exploitable vulnerabilities, and reports each one
with the exact line, the full reasoning behind it, its CWE and OWASP Top 10 category, and a secure
replacement for the vulnerable code. It never changes your code unless you approve a specific fix.

- **Two interfaces, one engine.** A web UI on a localhost port you choose, and a CLI that writes
  `findings.json` and `report.txt` (plus SARIF and Markdown).
- **Your choice of LLM.** Anthropic, OpenAI, xAI Grok or a local Ollama model. Nothing else is accepted.
- **Consistent results.** Deterministic pre-processing, temperature 0, seeds, majority voting, a response
  cache and a fixed severity formula.
- **Line-accurate.** The model must quote the code it flags; Argus checks the quote against the file and
  drops findings that do not match.
- **Asks when it cannot know.** Findings that depend on facts outside the code are marked
  *needs context* with one specific question for you.
- **Custom rules.** Add your own regex rules, taint sources/sinks/sanitizers, or plain-English policies
  that the AI enforces.
- **GitHub ready.** Scan a repository URL or a pull request, run it as a GitHub Action, upload SARIF to
  code scanning.

---

## Contents

1. [How it works](#how-it-works)
2. [Install](#install)
3. [First-time setup](#first-time-setup)
4. [Using the web UI](#using-the-web-ui)
5. [Using the terminal](#using-the-terminal)
6. [Reading results](#reading-results)
7. [Questions Argus asks you (needs context)](#questions-argus-asks-you-needs-context)
8. [Applying fixes (only with your consent)](#applying-fixes-only-with-your-consent)
9. [Choosing an LLM](#choosing-an-llm)
10. [Custom rules](#custom-rules)
11. [GitHub integration](#github-integration)
12. [Consistency](#consistency)
13. [Security and privacy](#security-and-privacy)
14. [Configuration reference](#configuration-reference)
15. [Project layout](#project-layout)
16. [Development](#development)
17. [Troubleshooting](#troubleshooting)
18. [Limitations](#limitations)

---

## How it works

```
 target ─► index ─► rules ─► Recon ─► Hunters ─► line check ─► Tracer ─► Verifier ─► Remediator ─► reports
 (file,    (tree-   (built-in  agent    agents     + voting       agent     agent       agent         JSON/TXT/
  folder,   sitter)  + custom)          (x votes)                                                     SARIF/MD
  GitHub)                                                                                            + patches
```

| Stage | Kind | What it does |
| --- | --- | --- |
| Target | code | Loads a file, a folder, a GitHub repo or a PR's changed files. Only `.java`, `.py`, `.js/.mjs/.cjs/.jsx` are scanned. |
| Index | code | Parses every file with tree-sitter into functions, cuts large files into function-aligned chunks, and redacts secrets before anything reaches an LLM. |
| Rules | code | Runs ~95 built-in rules plus your custom rules. Matches become findings (`report` rules) or hints that steer the AI (`hint`, `source`, `sink`, `sanitizer`). |
| Recon agent | AI, 1 call | Summarises frameworks, entry points, auth model and global protections for the other agents. |
| Hunter agents | AI | Review each chunk against an OWASP/CWE checklist (and your AI rules), several times ("votes"). |
| Line check + voting | code | Each finding's quoted evidence is matched against the real file (corrected within ±10 lines or dropped). Only issues found by a majority of votes survive. |
| Tracer agent | AI, tools | Follows data from source to sink across files using read-only tools (`read_lines`, `get_symbol`, `find_callers`, `search`). |
| Verifier agent | AI | A skeptical second opinion: **confirmed**, **needs_context** (with a question for you) or **rejected**. Also rates impact, attacker position and exploitability. |
| Severity | code | A fixed formula turns those three factors into critical / high / medium / low / info. |
| Remediator agent | AI | Writes replacement code for the vulnerable lines. Argus builds and validates the diff itself (it must apply and the file must still parse). |
| Reports | code | `findings.json`, `report.txt`, and optionally `findings.sarif` and `report.md`, plus one `.patch` per fix. |

Without an LLM (`--no-ai`), Argus still runs the rules and reports matches as **unverified**.

---

## Install

Requirements: Python 3.11+, and `git` if you scan GitHub repositories.

> **Argus is not published on PyPI yet.** Commands like `uv tool install argus-sast` or
> `pip install argus-sast` fail with *"argus-sast was not found in the package registry"*.
> Install from the source folder instead: the unzipped `argus-sast` folder, or your clone of the repository.

**With uv** (recommended):

```bash
cd /path/to/argus-sast                    # the folder that contains pyproject.toml
uv tool install .                         # installs the `argus` command in its own environment
# with OS keyring support for API keys:
uv tool install ".[keyring]"
# if `argus` is not found afterwards, add uv's tool folder to your PATH:
uv tool update-shell                      # then open a new terminal
```

Run it once without installing: `uvx --from /path/to/argus-sast argus --version`.

**With pipx or pip:**

```bash
cd /path/to/argus-sast
pipx install .                            # or ".[keyring]"
# or, inside a virtual environment:
pip install .
```

**From a git repository** (after you push Argus to GitHub):

```bash
uv tool install git+https://github.com/<you>/argus-sast
# or: pipx install git+https://github.com/<you>/argus-sast
```

To update after changing the code, run the same install command with `--force` (uv) or use
`pipx reinstall argus-sast`.

Check it works:

```bash
argus --version
argus scan examples/vulnerable --no-ai      # rules only, no LLM needed
```

---

## First-time setup

```bash
argus init
```

The wizard asks for:

1. **The port for the web UI** (default `8765`, must be 1024–65535 and free).
2. **The LLM provider**: `anthropic`, `openai`, `xai` or `ollama`. Anything else is rejected.
3. **The model** (a suggested default is filled in; `argus models` lists what your key can use).
4. **Your API key** (hidden input). It is stored in your OS keyring, or in
   `~/.config/argus/credentials.toml` with `0600` permissions if no keyring is available.
   It is never written to `config.toml` or to any report. Ollama needs no key, only its URL.

Non-interactive (CI, scripts):

```bash
argus init --port 9000 --provider openai --model gpt-5 --api-key "$OPENAI_API_KEY" --yes
# or skip storing keys and use environment variables:
export ANTHROPIC_API_KEY=...   # or OPENAI_API_KEY / XAI_API_KEY
```

Where things live:

```bash
argus config path
# config : ~/.config/argus/config.toml
# rules  : ~/.config/argus/rules/          <- your custom rules
# data   : ~/.local/share/argus/           <- scans, LLM cache, audit log
```

Set `ARGUS_HOME=/some/dir` to keep config and data together (handy for CI and testing).

---

## Using the web UI

```bash
argus serve            # uses the port from `argus init`
argus serve --open     # and open the browser
```

The terminal prints a link like `http://127.0.0.1:8765/?token=…`. Open it; the token is required and
changes every time the server starts.

| Page | What you do there |
| --- | --- |
| **Scans** | All scans from this machine (from the UI or the terminal), with severity counts. |
| **New scan** | Choose a folder, file, GitHub URL, pull request or uploaded file; turn AI on or off; pick provider, model, votes, OWASP edition and categories, languages, extra rule files. |
| **Scan page** | Live progress while scanning. Afterwards, a triage view: filter findings on the left, read the selected one on the right. The code viewer highlights the flagged line and numbers each data-flow step in the gutter. Below it: why it is flagged, how it could be exploited, impact, the secure fix as a diff, **Review and apply fix**, and downloads (JSON, text, SARIF, Markdown, patch). |
| **Questions for you** | Every open *needs context* question across recent scans, with an answer box. |
| **Rules** | All built-in and custom rules; switch any on or off; add a custom rule with a form or a YAML editor (with validation); delete your custom rules. |
| **Settings** | Provider, model, endpoint, API key (write-only), votes, tracer budget, call limits, cache, redaction, excludes, report formats and the UI port. |

---

## Using the terminal

```bash
# Scan a folder, a single file, a GitHub repo, or a PR
argus scan ./my-service
argus scan src/main/java/com/acme/LoginController.java
argus scan https://github.com/org/repo --ref develop
argus scan --github-pr org/repo#482

# Only files changed since a branch (local git repos)
argus scan . --since origin/main

# Rules only: no LLM, nothing leaves your machine
argus scan ./my-service --no-ai

# Pick a different LLM for one run
argus scan ./my-service --provider ollama --model qwen2.5-coder:14b

# Narrow the scope
argus scan . --categories A01,A05 --min-severity medium --languages java,python -x "**/generated/**"

# CI gate: exit code 1 if anything high or worse is found
argus scan . --fail-on high --format json,txt,sarif --out argus-results
```

Useful `scan` options:

| Option | Meaning |
| --- | --- |
| `--no-ai` | Pattern rules only. |
| `--provider`, `--model` | Override the configured LLM for this run. |
| `--rules PATH` / `-r` | Extra rule file or folder (repeatable). |
| `--votes N` | Self-consistency runs per chunk (1–7, default 3). |
| `--owasp 2025\|2021` | Edition used for categories in reports (both are always recorded). |
| `--categories A01,A05` | Only report these OWASP categories. |
| `--min-severity` | Hide findings below `info`/`low`/`medium`/`high`/`critical`. |
| `--mode focused` | Only send chunks with rule signals to the AI (cheaper on big repos). |
| `--no-trace` | Skip the Tracer agent (fewer calls, less detailed data flow). |
| `--max-llm-calls N` | Hard cap on LLM calls for this run. |
| `--no-cache` | Ask the model again even if the code is unchanged. |
| `--baseline FILE` | Suppress findings listed in a baseline (default `<target>/.argus-baseline.json`). |
| `--out DIR`, `--format` | Where reports go and which formats (`json`, `txt` always; `sarif`, `md` optional). |
| `--fail-on SEVERITY` | Exit code 1 if an active finding is at or above this severity. |

Other commands:

```bash
argus runs                                   # previous scans
argus findings list [--run ID] [--severity high] [--status needs_context|all] [--json]
argus findings show ARG-6A145EBC             # full detail: code, flow, explanation, patch
argus context answer ARG-1F0C2A9B "Only reachable over the corporate VPN"
argus context note ./my-service "All /admin routes sit behind an SSO proxy"
argus fix ARG-6A145EBC [--branch]            # review and apply ONE fix
argus baseline create --out .argus-baseline.json
argus models --provider xai                  # models available to your key
argus config show | set llm.model gpt-5 | set-key openai
argus rules list | new | validate | test | disable | enable
argus bench consistency ./my-service --runs 3
argus cache-clear
```

Exit codes: `0` success, `1` findings at/above `--fail-on`, `2` bad settings or a failed scan, `3` missing API key.

---

## Reading results

Every scan writes into `argus-results/<run-id>/` (and keeps a copy that the web UI reads):

| File | Contents |
| --- | --- |
| `findings.json` | Machine-readable results (schema below). |
| `report.txt` | Human-readable report: summary, then every finding with code, data flow, explanation, exploit scenario, impact and the suggested patch. |
| `findings.sarif` | SARIF 2.1.0 for GitHub code scanning and IDEs. |
| `report.md` | Shareable Markdown report. |
| `patches/<ID>.patch` | One unified diff per fix. **Never applied automatically.** |

### A finding

```json
{
  "id": "ARG-6A145EBC",
  "fingerprint": "6a145ebc9e...",
  "status": "confirmed",
  "title": "SQL injection via the name query parameter",
  "cwe": "CWE-89",
  "cwe_name": "SQL Injection",
  "owasp": { "2025": "A05", "2021": "A03" },
  "severity": "critical",
  "confidence": 0.9,
  "votes": "3/3",
  "detector": "ai+rule",
  "rule_id": "argus.python.sqli.format",
  "file": "python/app.py",
  "start_line": 26,
  "end_line": 26,
  "snippet": "cur.execute(f\"SELECT * FROM users WHERE name = '{name}'\")",
  "function": "get_user",
  "data_flow": [
    { "file": "python/app.py", "line": 24, "role": "source", "note": "request.args.get('name')" },
    { "file": "python/app.py", "line": 26, "role": "sink", "note": "interpolated into SQL" }
  ],
  "explanation": "Where the data enters, how it reaches line 26, why nothing stops it…",
  "exploit_scenario": "GET /user?name=' OR '1'='1 returns every row…",
  "impact": "Read access to the whole users table…",
  "severity_factors": { "impact": "data_breach", "attacker_position": "remote_unauthenticated", "exploitability": "easy" },
  "context_question": null,
  "remediation": {
    "summary": "Pass name as a bound parameter.",
    "start_line": 26, "end_line": 26,
    "fixed_code": "    cur.execute(\"SELECT * FROM users WHERE name = ?\", (name,))",
    "patch": "--- a/python/app.py\n+++ b/python/app.py\n@@ …",
    "patch_valid": true,
    "applied": false
  },
  "references": ["https://cwe.mitre.org/data/definitions/89.html"]
}
```

| Field | Meaning |
| --- | --- |
| `status` | `confirmed` (Verifier agrees), `needs_context` (you need to answer a question), `unverified` (rule match not checked by AI, or AI was unavailable), `rejected` (Verifier disproved it; kept for transparency), `suppressed` (inline comment or baseline). |
| `id` / `fingerprint` | Stable across runs: derived from file, CWE, enclosing function and the flagged code, not the line number. Moving code does not change it. |
| `detector` | `ai`, `rule`, or `ai+rule` when both found it. |
| `votes` | How many Hunter runs reported it (e.g. `2/3`). |
| `confidence` | Verifier confidence weighted by the vote ratio. |
| `severity` | Computed from `severity_factors` by a fixed formula, so the same facts always give the same severity. |
| `code_context` | The (redacted) code around the finding, as shown in the UI. |

The text report also lists **dangerous sinks the agents did not flag**, so text in the code that tries
to talk the AI out of reporting something cannot silently hide a risky call.

---

## Questions Argus asks you (needs context)

Some verdicts depend on things the code does not show: is this endpoint internet-facing? Does a gateway
validate this header? Can users set this field? Instead of guessing, the Verifier marks the finding
`needs_context` and asks **one specific question**.

Answer in the UI (**Questions for you**, or the box on the finding) or in the terminal:

```bash
argus context answer ARG-1F0C2A9B "Yes, /fetch is public and takes any URL"
```

Argus re-runs the Verifier for that finding with your answer, updates its status and severity, and
remembers the answer (keyed by fingerprint) for every future scan of the same project. For context that
applies to the whole project:

```bash
argus context note ./my-service "The admin API is only reachable through the internal VPN gateway"
```

Teams can also commit notes in `.argus.toml`:

```toml
[context]
notes = "All services run behind an Envoy gateway that enforces JWT auth."
```

---

## Applying fixes (only with your consent)

Argus never modifies code during a scan. The scanner opens files read-only; suggested fixes are stored as
patches. Applying one is a separate, explicit action for **one finding at a time**:

```bash
argus fix ARG-6A145EBC
```

Argus shows the diff and asks you to **type the finding ID** to confirm. Then it:

1. checks the file is unchanged since the scan (or finds the original lines exactly once; otherwise it refuses);
2. writes a backup `app.py.argus-bak` (or, with `--branch`, commits only that file to a new
   `argus/fix-<id>` git branch);
3. replaces only the shown lines (plus any new import lines);
4. records the change in the audit log (`~/.local/share/argus/audit.log`: who, when, finding, file hashes before and after).

In the UI, **Review and apply fix** opens the same diff, and **Apply fix** stays disabled until you type
the ID. There is no "fix everything" button. `--yes` (for scripts) still applies only the ID you name.

For repositories scanned from GitHub (temporary clones), apply the patch in your own checkout:
`git apply argus-results/<run>/patches/ARG-6A145EBC.patch`, or `argus fix ARG-… --target-root ~/src/repo`.

A fix that fails validation (it does not apply, the file no longer parses, or the region contains redacted
secrets) is shown as **guidance only** with the reason.

---

## Choosing an LLM

| Provider | `llm.provider` | Key | Notes |
| --- | --- | --- | --- |
| Anthropic | `anthropic` | `ANTHROPIC_API_KEY` | Uses structured outputs (`output_config` JSON schema); falls back to a forced tool call for older models, then to JSON in the prompt. Parameters a model rejects (such as `temperature` on Claude 5.5 models) are dropped automatically. |
| OpenAI | `openai` | `OPENAI_API_KEY` | JSON mode; seed sent; parameters a model rejects (e.g. `temperature` on reasoning models) are dropped automatically. |
| xAI Grok | `xai` | `XAI_API_KEY` | OpenAI-compatible API at `https://api.x.ai/v1`. |
| Ollama | `ollama` | none | Fully local; JSON-schema constrained output. Use a code model with a large context (16k+). Set `llm.base_url` for a remote Ollama host. |

```bash
argus config set llm.provider xai          # also resets the model to xai's suggested default
argus config set llm.model grok-4
argus models                               # what your key can use
```

Model names are free text, so new models work without an Argus release. Larger models give better
results; small local models work but find less.

**Cost control:** `scan.max_llm_calls` (hard stop), `--mode focused`, `--no-trace`, `--votes 1` for quick
checks, `--since` / PR mode for changed files only, and the cache (unchanged code is never re-asked).

---

## Custom rules

Custom rules are YAML files. Put them in your rules folder (`argus config path` shows it; usually
`~/.config/argus/rules/`) and every scan uses them, from the UI and the terminal. You can also pass files
per run with `--rules`, list folders in `[rules] paths`, or create rules in the web UI's **Rules** page.

There are five rule types:

| Type | What it does | Needs AI? |
| --- | --- | --- |
| `pattern` (mode `report`) | A regex match becomes a finding. With AI on, the Verifier confirms or rejects it (unless `verify: false`). | No |
| `pattern` (mode `hint`) | A match does not create a finding; it tells the Hunter agents to look closely at that line. | Yes |
| `sink` | Marks a dangerous operation, such as your own raw-SQL helper. | Yes |
| `source` | Marks where untrusted data enters, such as a legacy request wrapper. | Yes |
| `sanitizer` | Marks a function that makes data safe, which reduces false positives. | Yes |
| `ai` | A policy in plain English that every Hunter agent checks. | Yes |

### Example

```yaml
# ~/.config/argus/rules/acme.yaml
version: 1
rules:
  - id: acme.java.legacy-crypto              # unique; lowercase, digits, . _ -
    name: Deprecated LegacyCrypto helper
    type: pattern                            # pattern | ai | source | sink | sanitizer
    mode: report                             # report | hint   (pattern rules only)
    languages: [java]                        # java | python | javascript (default: all three)
    cwe: CWE-327                             # required for report rules and ai rules
    severity: high                           # critical | high | medium | low | info
    patterns:                                # Python regexes; any match fires
      - 'LegacyCrypto\.(encrypt|decrypt)\s*\('
    pattern-not:                             # skip lines that also match these
      - '//\s*approved-by-security'
    message: LegacyCrypto uses single DES with a static key.
    remediation: Use com.acme.crypto.CryptoService (AES-GCM, keys from KMS).
    references: ['https://wiki.acme.example/security/crypto']
    exclude: ['**/test/**']                  # path globs (also: include)

  - id: acme.ai.tenant-isolation
    name: Tenant isolation on data access
    type: ai
    cwe: CWE-639
    severity: high
    instruction: >
      Every query on customer data must be scoped to the tenant of the authenticated
      user (user.tenant_id / req.user.tenantId), never to a tenant id taken from the
      URL, query string, body or headers. Flag lookups that are not.
    remediation: Add a tenant filter taken from the authenticated principal.

  - id: acme.python.run-raw-sql
    type: sink
    languages: [python]
    cwe: CWE-89
    patterns: ['acme_db\.run_raw\s*\(']
    message: run_raw() executes its argument as SQL without parameters.
```

`examples/rules/acme-rules.yaml` contains one rule of every type.

### All fields

| Field | Applies to | Default | Description |
| --- | --- | --- | --- |
| `id` | all | required | Unique ID. Reusing a built-in ID **overrides** that built-in rule. |
| `name` | all | the id | Short title used for findings. |
| `type` | all | `pattern` | `pattern`, `ai`, `source`, `sink`, `sanitizer`. |
| `languages` | all | all three | `java`, `python`, `javascript` (aliases `js`, `py`). |
| `cwe` | all | – | `CWE-89` form. Determines the OWASP mapping. |
| `severity` | pattern, ai | `medium` | Used for rule-only findings; AI-verified findings use the severity formula. |
| `confidence` | pattern | `0.6` | Confidence for rule-only findings. |
| `patterns` | pattern, source, sink, sanitizer | required | List of Python regexes. |
| `pattern-not` | pattern | `[]` | Lines (or, with `scope: file`, the whole file) matching any of these are skipped. |
| `scope` | pattern | `line` | `file` runs patterns over the whole file, e.g. "a parser is created and the hardening call never appears". |
| `case_sensitive` | pattern | `true` | |
| `include_comments` | pattern | `false` | Comment lines are skipped unless this is true. |
| `mode` | pattern | `report` | `report` creates findings; `hint` only guides the AI. |
| `verify` | pattern | `true` | With AI on, ask the Verifier to confirm. `false` reports matches as confirmed (use for near-certain matches like committed private keys). |
| `instruction` | ai | required | The policy, in plain English. |
| `message` | all | `""` | Why it matters (shown in findings and given to the agents). |
| `remediation` | pattern, ai | `""` | How to fix; used as guidance and given to the Remediator. |
| `references` | all | `[]` | Links. |
| `include` / `exclude` | all | `[]` | Path globs the rule applies to / skips. |
| `tags` | all | `[]` | Free-form labels. |
| `enabled` | all | `true` | |

### Workflow

```bash
argus rules new acme.java.legacy-crypto --type pattern --lang java   # starter file in your rules folder
$EDITOR ~/.config/argus/rules/acme.java.legacy-crypto.yaml
argus rules validate                                                  # exit 1 on any error (good for CI)
argus rules test ~/.config/argus/rules/acme.java.legacy-crypto.yaml ./src   # show every match, no AI
argus rules list --custom
argus rules disable argus.common.cleartext-http-url                  # switch off any rule, built-in or custom
```

Load order (a later rule with the same ID replaces an earlier one): built-in packs, then your rules folder,
then `[rules] paths`, then `--rules`, then project rules. A broken rule file never stops a scan; its errors
are shown as warnings.

**Project rules** (`<repo>/.argus/rules/*.yaml`) are ignored unless you set
`scan.load_project_rules = true`. A scanned repository is untrusted: its rules could disable checks to hide
its own bugs, or carry prompt-injection text into AI rules.

### Suppressing a finding

```python
data = pickle.loads(blob)  # argus-ignore[CWE-502] internal queue, signed messages
```

`argus-ignore` (everything), `argus-ignore[CWE-502]` or `argus-ignore: rule-id` work on the same line or on a
comment line just above. Suppressed findings stay in the JSON with status `suppressed`.

To accept all current findings (so CI fails only on new ones): `argus baseline create` and commit
`.argus-baseline.json` at the repository root.

---

## GitHub integration

| Need | How |
| --- | --- |
| Scan any repository | `argus scan https://github.com/org/repo [--ref branch]`; set `GITHUB_TOKEN` for private repos. |
| Scan a pull request | `argus scan --github-pr org/repo#123` (changed files only). |
| Run in CI | Use the bundled action (`action/action.yml`). |
| Code scanning alerts | Upload `findings.sarif`; findings show under **Security → Code scanning** and as PR annotations. |

Example workflow (`.github/workflows/argus.yml`, also in `examples/github-workflow.yml`):

```yaml
name: Argus SAST
on:
  pull_request:
  push:
    branches: [main]
permissions:
  contents: read
  security-events: write     # to upload SARIF
jobs:
  argus:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with: { fetch-depth: 0 }
      - uses: <you>/argus-sast/action@v1
        with:
          provider: anthropic
          model: claude-sonnet-5-5
          fail-on: high
          changed-only: ${{ github.event_name == 'pull_request' }}
        env:
          ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
```

The token is passed to git through environment configuration, never on the command line, and clones have
git hooks disabled.

---

## Consistency

LLMs are not deterministic, even at temperature 0. Argus layers several controls so the same code gives the
same results:

| Control | Effect |
| --- | --- |
| Deterministic chunking, ordering and prompts | The model sees exactly the same input every run. |
| Temperature 0 and a fixed seed (where supported) | Less sampling noise. |
| Closed output schemas (Pydantic) with fixed verdicts and severity factors | No free-form labels; invalid output is retried once, then dropped. |
| Majority voting (`scan.votes`, default 3) | One-off hallucinations do not survive. |
| Content-addressed response cache | Unchanged code returns the stored answer: re-scans are identical and free. |
| Severity formula | Same facts, same severity. |
| Stable fingerprints and IDs | The same issue keeps its ID across runs and small refactors. |
| Versioned prompts | Each finding records the prompt version and model that produced it. |

Measure it on your code: `argus bench consistency ./src --runs 3` (cache off; prints the Jaccard similarity
of finding fingerprints between runs).

---

## Security and privacy

Argus is a security tool that reads untrusted code and has a button that edits files, so it treats itself as a target.

- **Prompt injection.** Code is wrapped in nonce-tagged `<untrusted_code>` fences, and every agent is told
  never to follow instructions inside them. Rule matching does not depend on the LLM. Text addressed to AI
  reviewers is itself reported (CWE-1427), and dangerous sinks the agents did not flag are listed in the report.
- **Secrets.** Keys, tokens, passwords and private keys are redacted before code is sent to a provider.
  Line numbers are preserved. Reports show the redacted text.
- **Your code and providers.** With `anthropic`, `openai` or `xai`, code chunks are sent to that provider.
  Use `ollama` or `--no-ai` to keep everything on your machine.
- **Read-only agents.** Agent tools can only read files inside the scan root (path traversal and escaping
  symlinks are blocked). They have no write, shell or network access, and their calls are budgeted.
- **Untrusted repositories.** A repo's `.argus.toml` may only set `scan.exclude`, `scan.languages`,
  `scan.categories` and `scan.min_severity`. It cannot change the LLM endpoint or disable rules. Its
  `.argus/rules` are ignored unless you opt in.
- **Web UI.** Binds to `127.0.0.1` (other addresses need `--allow-remote`). It uses a per-start access token
  in an HttpOnly, SameSite=Strict cookie, a Host-header allowlist (against DNS rebinding), CSRF tokens and an
  Origin check on every change, and a strict Content-Security-Policy. Code and model output are always
  rendered as text, never HTML. API keys are write-only in the UI.
- **Fixes.** Applied one at a time after you confirm, with a backup and an audit log entry.

---

## Configuration reference

`~/.config/argus/config.toml` (edit by hand, with `argus config set`, or in the UI). Environment variables
override it: `ARGUS_<SECTION>__<KEY>`, e.g. `ARGUS_LLM__MODEL=gpt-5`, `ARGUS_SCAN__VOTES=1`.

```toml
[server]
host = "127.0.0.1"
port = 8765                  # chosen during `argus init`
allow_remote = false

[llm]
provider = "anthropic"       # anthropic | openai | xai | ollama
model = "claude-sonnet-5-5"
# base_url = "http://gpu-box:11434"   # optional endpoint override
temperature = 0.0
seed = 1337
max_tokens = 16000           # at least 16000 is used for cloud models (thinking counts against it)
max_concurrency = 4
timeout_seconds = 180

[scan]
languages = ["java", "python", "javascript"]
owasp_edition = "2025"       # or "2021"
categories = []              # e.g. ["A01", "A05"]; empty = all
votes = 3
min_severity = "low"
mode = "full"                # or "focused"
hunters = "combined"         # or "specialist" (one hunter per OWASP group)
trace = true
tool_budget = 6
chunk_max_lines = 400
max_file_bytes = 1000000
max_llm_calls = 2000
use_cache = true
strict_taxonomy = false      # true = drop findings whose CWE Argus does not know
redact_secrets = true
load_project_rules = false
exclude = ["**/node_modules/**", "**/.git/**", "**/venv/**", "**/dist/**", "**/build/**", "**/*.min.js"]

[rules]
paths = []                   # extra rule files/folders
disable = []                 # rule IDs to switch off

[remediation]
enabled = true
require_consent = true       # cannot be turned off

[output]
dir = "argus-results"
formats = ["json", "txt", "sarif"]   # json and txt are always written; "md" is optional
```

---

## Project layout

```
argus/
  cli.py              Typer CLI (every command above)
  config.py           settings model, layering, TOML read/write
  credentials.py      API keys: env, OS keyring, 0600 fallback file
  targets.py          file / folder / GitHub repo / PR / --since resolution
  index.py            tree-sitter functions, chunking, tracer tool backends
  security.py         secret redaction, prompt fences, path sandbox
  taxonomy.py         OWASP 2025 + 2021 <-> CWE mapping (from OWASP's own lists)
  rules/              rule schema, loader (custom rules), engine, built-in packs (YAML)
  llm/                provider adapters (Anthropic, OpenAI, xAI, Ollama), client, cache
  agents/             Recon, Hunter, Tracer, Verifier, Remediator; prompts; output schemas
  findings.py         finding model, line verification, voting, fingerprints, severity formula
  pipeline.py         ScanService: the orchestrator used by CLI, UI and CI
  remediation.py      builds and validates patches from the Remediator's answer
  fixer.py            the only code that writes to your source, after consent
  reports.py          JSON, TXT, SARIF 2.1.0, Markdown
  store.py            scan runs, context answers, baselines, audit log
  web/                FastAPI app, templates, CSS, JS
action/action.yml     GitHub Action
examples/             deliberately vulnerable apps and example custom rules
tests/                pytest suite (uses a scripted fake LLM; no keys needed)
```

Each module starts with a comment explaining its part of the flow, and the important steps inside are
commented where they happen.

---

## Development

```bash
# with uv
uv venv && uv pip install -e ".[dev]"
uv run pytest -q                # 55 tests, offline, about 5 seconds
uv run ruff check argus tests

# or with pip
python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
pytest -q
```

The tests use `tests/fake_llm.py`, a scripted model that answers like a well-behaved LLM, to exercise the whole
agent pipeline (voting, hallucination dropping, tracer tools, verdicts, patches, re-verification), and
mocked HTTP transports to check each provider adapter's request format. The fake is not selectable in
config; only the four real providers are.

To try the UI with realistic data and no API key: `argus scan examples/vulnerable --no-ai`, then `argus serve`.

---

## Troubleshooting

| Message | Cause and fix |
| --- | --- |
| `argus-sast was not found in the package registry` | Argus is not on PyPI yet. Install from the source folder: `uv tool install .` (see [Install](#install)). |
| `tool_choice: type "tool" and "any" are not supported for this model` | Fixed in this version: Argus now uses structured outputs and picks a mechanism the model accepts. Reinstall with `uv tool install --force .`. |
| `temperature: Extra inputs are not permitted` | Some models do not accept sampling settings; Argus drops the parameter and remembers it for that model. |
| `AI analysis failed for every code chunk` | Every LLM call failed (key, model name, network or quota). The first error is shown; results contain only pattern-rule matches. Check `argus models` and your API key. |
| `the reply hit max_tokens before the JSON was complete` | Raise `llm.max_tokens` (`argus config set llm.max_tokens 32000`). |
| `No API key for ...` | Run `argus init`, set the provider's environment variable, or use `--provider ollama` / `--no-ai`. |

---

## Limitations

- Only Java, Python and JavaScript in this version. TypeScript and other languages can be added through the
  index and rule packs.
- Argus is not a dependency (SCA), infrastructure-as-code or dynamic (DAST) scanner. It flags risky use of
  components in code, but use a dedicated SCA tool for known-vulnerable package versions.
- AI findings are probabilistic. Treat `confirmed` as "a careful reviewer agreed", not as proof. The quality
  of results depends on the model you choose.
- Cross-file tracing is bounded by the Tracer's tool budget; very long call chains may end in `needs_context`.

## License

Apache License 2.0. See [LICENSE](LICENSE).
