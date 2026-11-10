"""Configuration: one Pydantic model, several layers.

Layer order (later wins):

    1. built-in defaults           (the field defaults below)
    2. user config                 ~/.config/argus/config.toml
    3. project config              <target>/.argus.toml   (SAFE KEYS ONLY)
    4. environment variables       ARGUS_<SECTION>__<KEY>, e.g. ARGUS_LLM__MODEL
    5. per-run overrides           CLI flags / web form

The CLI and the web UI both read and write through this module, so the two
interfaces can never disagree about the active settings.

Security notes
--------------
* API keys are NEVER stored here; see ``argus.credentials``.
* A scanned repository is untrusted. Its ``.argus.toml`` may only change a
  small allowlist of scan-scoping keys (``PROJECT_SAFE_KEYS``). It cannot, for
  example, point ``llm.base_url`` at an attacker's server to exfiltrate code,
  or disable rules to hide its own vulnerabilities.
"""

from __future__ import annotations

import copy
import os
from enum import Enum
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field, field_validator

try:  # Python 3.11+
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - 3.10 fallback
    import tomli as tomllib  # type: ignore


# --------------------------------------------------------------------------- #
# Enumerations shared across the code base
# --------------------------------------------------------------------------- #
class ProviderName(str, Enum):
    """The ONLY LLM providers Argus supports. Anything else fails validation
    before a single line of code is sent anywhere."""

    ANTHROPIC = "anthropic"
    OPENAI = "openai"
    XAI = "xai"  # Grok
    OLLAMA = "ollama"


class Language(str, Enum):
    JAVA = "java"
    PYTHON = "python"
    JAVASCRIPT = "javascript"


# Suggested defaults shown by `argus init`. Users can type any model name the
# provider offers; `argus models --provider X` lists what their key can use.
DEFAULT_MODELS: dict[ProviderName, str] = {
    ProviderName.ANTHROPIC: "claude-sonnet-5-5",
    ProviderName.OPENAI: "gpt-5",
    ProviderName.XAI: "grok-4",
    ProviderName.OLLAMA: "qwen2.5-coder:14b",
}

DEFAULT_BASE_URLS: dict[ProviderName, str] = {
    ProviderName.ANTHROPIC: "https://api.anthropic.com",
    ProviderName.OPENAI: "https://api.openai.com/v1",
    ProviderName.XAI: "https://api.x.ai/v1",
    ProviderName.OLLAMA: "http://localhost:11434",
}

SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]


# --------------------------------------------------------------------------- #
# Settings sections
# --------------------------------------------------------------------------- #
class ServerSettings(BaseModel):
    host: str = "127.0.0.1"
    port: int = Field(8765, ge=1024, le=65535)
    # Binding to anything other than loopback must be explicitly allowed.
    allow_remote: bool = False


class LLMSettings(BaseModel):
    provider: ProviderName = ProviderName.ANTHROPIC
    model: str = DEFAULT_MODELS[ProviderName.ANTHROPIC]
    base_url: str | None = None  # None -> provider default
    temperature: float = Field(0.0, ge=0.0, le=1.0)
    seed: int = 1337  # sent to providers that support it
    # Floor of 16000 is applied for Anthropic/OpenAI/xAI: thinking/reasoning tokens count against it.
    max_tokens: int = Field(16000, ge=256, le=128000)
    max_concurrency: int = Field(4, ge=1, le=32)
    timeout_seconds: int = Field(180, ge=10, le=1800)


class ScanSettings(BaseModel):
    languages: list[Language] = Field(default_factory=lambda: list(Language))
    owasp_edition: str = "2025"  # "2025" or "2021" (both are always recorded)
    categories: list[str] = Field(default_factory=list)  # e.g. ["A01","A05"]; empty = all
    votes: int = Field(3, ge=1, le=7)  # self-consistency runs per chunk
    min_severity: str = "low"
    mode: str = "full"  # "full" = every chunk; "focused" = chunks with rule signals only
    hunters: str = "combined"  # "combined" = one hunter; "specialist" = one per OWASP group
    trace: bool = True  # run the Tracer agent (cross-file data flow)
    tool_budget: int = Field(6, ge=0, le=25)  # max tool calls per Tracer run
    chunk_max_lines: int = Field(400, ge=50, le=3000)
    max_file_bytes: int = 1_000_000
    max_llm_calls: int = Field(2000, ge=1)  # hard stop for cost control
    use_cache: bool = True
    strict_taxonomy: bool = False  # drop findings whose CWE is not in Argus's taxonomy
    redact_secrets: bool = True  # redact secrets before code is sent to an LLM
    load_project_rules: bool = False  # trust <target>/.argus/rules/*.yaml
    exclude: list[str] = Field(
        default_factory=lambda: [
            "**/node_modules/**",
            "**/.git/**",
            "**/venv/**",
            "**/.venv/**",
            "**/site-packages/**",
            "**/dist/**",
            "**/build/**",
            "**/target/**",
            "**/*.min.js",
            "**/*.bundle.js",
        ]
    )

    @field_validator("owasp_edition")
    @classmethod
    def _edition(cls, v: str) -> str:
        if v not in ("2025", "2021"):
            raise ValueError("owasp_edition must be '2025' or '2021'")
        return v

    @field_validator("min_severity")
    @classmethod
    def _sev(cls, v: str) -> str:
        if v not in SEVERITY_ORDER:
            raise ValueError(f"min_severity must be one of {SEVERITY_ORDER}")
        return v

    @field_validator("mode")
    @classmethod
    def _mode(cls, v: str) -> str:
        if v not in ("full", "focused"):
            raise ValueError("mode must be 'full' or 'focused'")
        return v

    @field_validator("hunters")
    @classmethod
    def _hunters(cls, v: str) -> str:
        if v not in ("combined", "specialist"):
            raise ValueError("hunters must be 'combined' or 'specialist'")
        return v

    @field_validator("categories")
    @classmethod
    def _cats(cls, v: list[str]) -> list[str]:
        out = []
        for c in v:
            c = c.strip().upper()
            if not (len(c) == 3 and c[0] == "A" and c[1:].isdigit() and 1 <= int(c[1:]) <= 10):
                raise ValueError(f"invalid OWASP category {c!r}; use A01..A10")
            out.append(c)
        return out


class RulesSettings(BaseModel):
    # Extra rule files or folders (YAML). ~/.config/argus/rules is always loaded.
    paths: list[str] = Field(default_factory=list)
    # Rule IDs to switch off (built-in or custom).
    disable: list[str] = Field(default_factory=list)


class RemediationSettings(BaseModel):
    enabled: bool = True
    # Consent is not configurable: Argus never changes code without an explicit
    # per-finding approval. The field exists only so the setting is visible.
    require_consent: bool = True

    @field_validator("require_consent")
    @classmethod
    def _always(cls, v: bool) -> bool:
        if not v:
            raise ValueError("require_consent cannot be disabled")
        return True


class OutputSettings(BaseModel):
    dir: str = "argus-results"
    formats: list[str] = Field(default_factory=lambda: ["json", "txt", "sarif"])

    @field_validator("formats")
    @classmethod
    def _fmts(cls, v: list[str]) -> list[str]:
        allowed = {"json", "txt", "sarif", "md"}
        bad = [f for f in v if f not in allowed]
        if bad:
            raise ValueError(f"unknown output format(s) {bad}; allowed {sorted(allowed)}")
        # JSON and TXT are always produced (they are the contract of the tool).
        return sorted(set(v) | {"json", "txt"}, key=["json", "txt", "sarif", "md"].index)


class Settings(BaseModel):
    server: ServerSettings = Field(default_factory=ServerSettings)
    llm: LLMSettings = Field(default_factory=LLMSettings)
    scan: ScanSettings = Field(default_factory=ScanSettings)
    rules: RulesSettings = Field(default_factory=RulesSettings)
    remediation: RemediationSettings = Field(default_factory=RemediationSettings)
    output: OutputSettings = Field(default_factory=OutputSettings)


# Keys a scanned repo's .argus.toml is allowed to set (see module docstring).
PROJECT_SAFE_KEYS = {
    ("scan", "exclude"),
    ("scan", "languages"),
    ("scan", "categories"),
    ("scan", "min_severity"),
}


# --------------------------------------------------------------------------- #
# Paths
# --------------------------------------------------------------------------- #
def config_dir() -> Path:
    """~/.config/argus (or $ARGUS_HOME/config for tests / portable installs)."""
    if os.environ.get("ARGUS_HOME"):
        return Path(os.environ["ARGUS_HOME"]) / "config"
    base = os.environ.get("XDG_CONFIG_HOME") or str(Path.home() / ".config")
    return Path(base) / "argus"


def data_dir() -> Path:
    """~/.local/share/argus: runs, LLM cache, audit log, context answers."""
    if os.environ.get("ARGUS_HOME"):
        return Path(os.environ["ARGUS_HOME"]) / "data"
    base = os.environ.get("XDG_DATA_HOME") or str(Path.home() / ".local" / "share")
    return Path(base) / "argus"


def user_config_path() -> Path:
    return config_dir() / "config.toml"


def user_rules_dir() -> Path:
    return config_dir() / "rules"


# --------------------------------------------------------------------------- #
# Loading
# --------------------------------------------------------------------------- #
def _deep_merge(base: dict, override: dict) -> dict:
    out = copy.deepcopy(base)
    for k, v in override.items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _deep_merge(out[k], v)
        else:
            out[k] = v
    return out


def _read_toml(path: Path) -> dict:
    if not path.is_file():
        return {}
    with path.open("rb") as fh:
        return tomllib.load(fh)


def _env_overrides() -> dict:
    """ARGUS_LLM__MODEL=x  ->  {"llm": {"model": "x"}}. Lists are comma separated."""
    out: dict[str, Any] = {}
    for key, value in os.environ.items():
        if not key.startswith("ARGUS_") or "__" not in key:
            continue
        section, _, field = key[len("ARGUS_"):].lower().partition("__")
        if section not in Settings.model_fields:
            continue
        section_model = Settings.model_fields[section].annotation
        info = section_model.model_fields.get(field)  # type: ignore[union-attr]
        if info is None:
            continue
        ann = str(info.annotation)
        parsed: Any = value
        if ann.startswith("list"):
            parsed = [x.strip() for x in value.split(",") if x.strip()]
        out.setdefault(section, {})[field] = parsed
    return out


def project_overrides(target_root: Path | None) -> tuple[dict, dict]:
    """Read <target>/.argus.toml. Returns (safe scan overrides, context section).

    Unsafe keys are silently ignored (and reported by ``argus config show``).
    """
    if target_root is None:
        return {}, {}
    raw = _read_toml(Path(target_root) / ".argus.toml")
    safe: dict[str, dict] = {}
    for section, values in raw.items():
        if not isinstance(values, dict):
            continue
        for k, v in values.items():
            if (section, k) in PROJECT_SAFE_KEYS:
                safe.setdefault(section, {})[k] = v
    context = raw.get("context", {}) if isinstance(raw.get("context"), dict) else {}
    return safe, context


def load_settings(
    overrides: dict | None = None,
    target_root: Path | None = None,
    config_path: Path | None = None,
) -> Settings:
    """Build the effective Settings for one run by stacking every layer."""
    merged: dict = Settings().model_dump(mode="json")
    merged = _deep_merge(merged, _read_toml(config_path or user_config_path()))
    proj, _ = project_overrides(target_root)
    merged = _deep_merge(merged, proj)
    merged = _deep_merge(merged, _env_overrides())
    if overrides:
        merged = _deep_merge(merged, {k: v for k, v in overrides.items() if v is not None})
    return Settings.model_validate(merged)


def save_user_settings(settings: Settings, path: Path | None = None) -> Path:
    """Persist settings to the user config file (0600 permissions)."""
    path = path or user_config_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    data = settings.model_dump(mode="json")
    path.write_text(dump_toml(data), encoding="utf-8")
    try:
        os.chmod(path, 0o600)
    except OSError:  # pragma: no cover - e.g. Windows
        pass
    return path


def set_config_value(dotted_key: str, raw_value: str, path: Path | None = None) -> Settings:
    """`argus config set llm.provider ollama` -> validate and persist."""
    current = load_settings(config_path=path)
    data = current.model_dump(mode="json")
    section, _, field = dotted_key.partition(".")
    if section not in data or field not in data[section]:
        raise KeyError(f"unknown setting {dotted_key!r}")
    old = data[section][field]
    value: Any
    if isinstance(old, bool):
        value = raw_value.lower() in ("1", "true", "yes", "on")
    elif isinstance(old, int) and not isinstance(old, bool):
        value = int(raw_value)
    elif isinstance(old, float):
        value = float(raw_value)
    elif isinstance(old, list):
        value = [x.strip() for x in raw_value.split(",") if x.strip()]
    elif old is None and raw_value.lower() in ("", "none", "null"):
        value = None
    else:
        value = raw_value
    data[section][field] = value
    # Changing provider without a model: switch to that provider's suggested model.
    if dotted_key == "llm.provider":
        if value not in {p.value for p in ProviderName}:
            raise ValueError(
                f"unsupported provider {value!r}; Argus supports: {', '.join(p.value for p in ProviderName)}"
            )
        data["llm"]["model"] = DEFAULT_MODELS[ProviderName(value)]
        data["llm"]["base_url"] = None
    settings = Settings.model_validate(data)
    save_user_settings(settings, path)
    return settings


# --------------------------------------------------------------------------- #
# Minimal TOML writer (the stdlib only reads TOML). Our config is a two-level
# table of scalars and lists of scalars, so a tiny writer is enough.
# --------------------------------------------------------------------------- #
def _toml_scalar(v: Any) -> str:
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, (int, float)):
        return repr(v)
    if isinstance(v, str):
        escaped = v.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")
        return f'"{escaped}"'
    if isinstance(v, list):
        return "[" + ", ".join(_toml_scalar(x) for x in v) + "]"
    raise TypeError(f"cannot write {type(v).__name__} to TOML")


def dump_toml(data: dict) -> str:
    lines = ["# Argus configuration. Edit by hand, with `argus config set`, or in the web UI.", ""]
    for section, values in data.items():
        if not isinstance(values, dict):
            if values is not None:
                lines.append(f"{section} = {_toml_scalar(values)}")
            continue
        lines.append(f"[{section}]")
        for k, v in values.items():
            if v is None:
                continue  # TOML has no null: omitted keys fall back to defaults
            lines.append(f"{k} = {_toml_scalar(v)}")
        lines.append("")
    return "\n".join(lines)
