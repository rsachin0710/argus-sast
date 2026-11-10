"""Load, merge and validate rule files.

Load order (a later rule with the same `id` REPLACES the earlier one, so you
can override any built-in rule by redefining its id in your own file):

    1. built-in packs        argus/rules/builtin/*.yaml
    2. user rules            ~/.config/argus/rules/*.yaml   (always loaded)
    3. configured paths      [rules] paths = [...]          in config.toml
    4. CLI / UI paths        argus scan --rules my-rules.yaml
    5. project rules         <target>/.argus/rules/*.yaml   ONLY when
                             scan.load_project_rules = true (a scanned repo is
                             untrusted: its rules could hide its own bugs or
                             carry prompt-injection text into AI rules)

Finally every id in [rules] disable = [...] is switched off.

Broken rule files never crash a scan: each problem is collected as a
``RuleLoadError`` and shown to the user; `argus rules validate` turns them into
a non-zero exit code for CI.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import yaml
from pydantic import ValidationError

from ..config import Language, Settings, user_rules_dir
from .model import Rule, RuleFile, RuleType

BUILTIN_DIR = Path(__file__).parent / "builtin"


@dataclass
class RuleLoadError:
    source: str
    message: str
    rule_id: str | None = None

    def __str__(self) -> str:
        where = f"{self.source}" + (f" [{self.rule_id}]" if self.rule_id else "")
        return f"{where}: {self.message}"


@dataclass
class RuleSet:
    rules: dict[str, Rule] = field(default_factory=dict)
    errors: list[RuleLoadError] = field(default_factory=list)
    overridden: list[str] = field(default_factory=list)

    def active(self, language: Language | None = None, types: set[RuleType] | None = None) -> list[Rule]:
        out = []
        for r in self.rules.values():
            if not r.enabled:
                continue
            if language is not None and language not in r.languages:
                continue
            if types is not None and r.type not in types:
                continue
            out.append(r)
        return sorted(out, key=lambda r: r.id)

    def ai_rules(self) -> list[Rule]:
        return self.active(types={RuleType.AI})

    def get(self, rule_id: str) -> Rule | None:
        return self.rules.get(rule_id)


def _iter_rule_files(path: Path) -> list[Path]:
    if path.is_file():
        return [path]
    if path.is_dir():
        return sorted([*path.glob("*.yaml"), *path.glob("*.yml")])
    return []


def parse_rule_file(path: Path, origin: str) -> tuple[list[Rule], list[RuleLoadError]]:
    """Parse one YAML file into validated Rule objects."""
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))  # safe_load: never executes tags
    except (OSError, yaml.YAMLError) as exc:
        return [], [RuleLoadError(str(path), f"cannot read YAML: {exc}")]
    return parse_rule_data(raw, str(path), origin)


def parse_rule_data(raw, source: str, origin: str) -> tuple[list[Rule], list[RuleLoadError]]:
    """Validate already-parsed YAML/JSON data (used by files and the web UI)."""
    rules: list[Rule] = []
    errors: list[RuleLoadError] = []
    if raw is None:
        return [], []
    if isinstance(raw, list):  # allow a bare list of rules
        raw = {"rules": raw}
    try:
        rf = RuleFile.model_validate(raw)
    except ValidationError as exc:
        return [], [RuleLoadError(source, _fmt(exc))]
    seen: set[str] = set()
    for i, item in enumerate(rf.rules):
        rid = item.get("id") if isinstance(item, dict) else None
        try:
            rule = Rule.model_validate(item)
        except ValidationError as exc:
            errors.append(RuleLoadError(source, _fmt(exc), rid or f"#{i + 1}"))
            continue
        if rule.id in seen:
            errors.append(RuleLoadError(source, "duplicate id in the same file", rule.id))
            continue
        seen.add(rule.id)
        rule.origin = origin
        rule.source_file = source
        rules.append(rule)
    return rules, errors


def _fmt(exc: ValidationError) -> str:
    parts = []
    for e in exc.errors():
        loc = ".".join(str(p) for p in e["loc"])
        parts.append(f"{loc}: {e['msg']}" if loc else e["msg"])
    return "; ".join(parts)


def load_rules(
    settings: Settings,
    extra_paths: list[str | Path] | None = None,
    target_root: Path | None = None,
    include_builtin: bool = True,
) -> RuleSet:
    rs = RuleSet()

    def add(paths: list[Path], origin: str) -> None:
        for p in paths:
            rules, errors = parse_rule_file(p, origin)
            rs.errors.extend(errors)
            for r in rules:
                if r.id in rs.rules:
                    rs.overridden.append(r.id)
                rs.rules[r.id] = r

    if include_builtin:
        add(_iter_rule_files(BUILTIN_DIR), "builtin")
    add(_iter_rule_files(user_rules_dir()), "user")
    for p in settings.rules.paths:
        files = _iter_rule_files(Path(p).expanduser())
        if not files:
            rs.errors.append(RuleLoadError(str(p), "rules path not found"))
        add(files, "config")
    for p in extra_paths or []:
        files = _iter_rule_files(Path(p).expanduser())
        if not files:
            rs.errors.append(RuleLoadError(str(p), "rules path not found"))
        add(files, "cli")
    if target_root is not None and settings.scan.load_project_rules:
        add(_iter_rule_files(Path(target_root) / ".argus" / "rules"), "project")

    for rid in settings.rules.disable:
        if rid in rs.rules:
            rs.rules[rid].enabled = False
    return rs


# --------------------------------------------------------------------------- #
# Writing custom rules (used by `argus rules new` and the web UI)
# --------------------------------------------------------------------------- #
def rule_to_yaml(rule_data: dict) -> str:
    """Serialise one rule dict as a complete rules file."""
    clean = {k: v for k, v in rule_data.items() if v not in (None, "", [], {})}
    return yaml.safe_dump({"version": 1, "rules": [clean]}, sort_keys=False, allow_unicode=True)


def save_custom_rule(rule_data: dict, directory: Path | None = None) -> Path:
    """Validate a rule and write it to ~/.config/argus/rules/<id>.yaml."""
    rules, errors = parse_rule_data({"rules": [rule_data]}, "<new rule>", "user")
    if errors:
        raise ValueError("; ".join(str(e) for e in errors))
    rule = rules[0]
    directory = directory or user_rules_dir()
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / f"{rule.id}.yaml"
    path.write_text(rule_to_yaml(rule_data), encoding="utf-8")
    return path


SCAFFOLDS = {
    "pattern": {
        "id": "my-org.java.example",
        "name": "Describe what this rule catches",
        "type": "pattern",
        "languages": ["java"],
        "cwe": "CWE-89",
        "severity": "high",
        "mode": "report",
        "patterns": [r"rawQuery\s*\(.*\+"],
        "pattern-not": [r"//\s*argus-reviewed"],
        "message": "Why this line is dangerous.",
        "remediation": "How to fix it.",
        "references": ["https://cwe.mitre.org/data/definitions/89.html"],
    },
    "ai": {
        "id": "my-org.ai.example",
        "name": "Organisation policy the AI should enforce",
        "type": "ai",
        "languages": ["java", "python", "javascript"],
        "cwe": "CWE-639",
        "severity": "high",
        "instruction": (
            "Every database query on a tenant-scoped table must filter by the tenant id "
            "taken from the authenticated user, never from request parameters. "
            "Flag queries that do not."
        ),
        "remediation": "Filter by tenant id from the authenticated principal.",
    },
    "sink": {
        "id": "my-org.python.raw-sql-helper",
        "name": "Internal helper that executes raw SQL",
        "type": "sink",
        "languages": ["python"],
        "cwe": "CWE-89",
        "patterns": [r"db_utils\.run_raw\s*\("],
        "message": "run_raw() executes its argument as SQL without parameters.",
    },
    "source": {
        "id": "my-org.java.legacy-request",
        "name": "Legacy request wrapper (untrusted input)",
        "type": "source",
        "languages": ["java"],
        "patterns": [r"LegacyRequest\.param\s*\("],
        "message": "Returns raw, attacker-controlled request data.",
    },
    "sanitizer": {
        "id": "my-org.javascript.safe-html",
        "name": "Approved HTML sanitiser",
        "type": "sanitizer",
        "languages": ["javascript"],
        "patterns": [r"safeHtml\s*\("],
        "message": "Output of safeHtml() is HTML-safe.",
    },
}
