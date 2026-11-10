"""Rule schema: the format of every built-in AND custom detection rule.

A rules file is YAML:

    version: 1
    rules:
      - id: acme.java.legacy-crypto
        name: Use of the deprecated LegacyCrypto helper
        type: pattern            # pattern | ai | source | sink | sanitizer
        languages: [java]
        cwe: CWE-327
        severity: high
        patterns: ['LegacyCrypto\\.(encrypt|decrypt)\\s*\\(']
        message: LegacyCrypto uses DES.
        remediation: Use CryptoService.encrypt() instead.

Rule types
----------
pattern    Regex matched per line (or per file with `scope: file`).
           mode: report -> becomes a finding (then confirmed or rejected by the
                           Verifier agent when AI is on and `verify: true`)
           mode: hint   -> only steers the AI hunters ("look closely here").
ai         A natural-language check (`instruction`) added to every Hunter
           agent's checklist, e.g. an organisation-specific policy. Needs AI.
source     Marks where untrusted data enters (helps the Tracer/Verifier).
sink       Marks a dangerous operation (e.g. your own raw-SQL wrapper).
sanitizer  Marks a function that makes data safe (reduces false positives).
"""

from __future__ import annotations

import re
from enum import Enum

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from ..config import Language
from ..taxonomy import cwe_label, parse_cwe

RULE_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{2,119}$")


class RuleType(str, Enum):
    PATTERN = "pattern"
    AI = "ai"
    SOURCE = "source"
    SINK = "sink"
    SANITIZER = "sanitizer"


class RuleMode(str, Enum):
    REPORT = "report"
    HINT = "hint"


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Rule(BaseModel):
    # YAML users may write `pattern-not:` or `pattern_not:`; both are accepted.
    model_config = ConfigDict(populate_by_name=True, extra="forbid")

    id: str
    name: str = ""
    type: RuleType = RuleType.PATTERN
    languages: list[Language] = Field(default_factory=lambda: list(Language))
    cwe: str | None = None
    severity: Severity = Severity.MEDIUM
    confidence: float = Field(0.6, ge=0.0, le=1.0)
    message: str = ""
    # --- pattern / source / sink / sanitizer ---
    patterns: list[str] = Field(default_factory=list)
    pattern_not: list[str] = Field(default_factory=list, alias="pattern-not")
    scope: str = "line"  # "line" | "file"
    case_sensitive: bool = True
    include_comments: bool = False
    mode: RuleMode = RuleMode.REPORT
    verify: bool = True
    # --- ai ---
    instruction: str = ""
    # --- shared metadata ---
    remediation: str = ""
    references: list[str] = Field(default_factory=list)
    include: list[str] = Field(default_factory=list)  # path globs
    exclude: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    enabled: bool = True
    # Filled in by the loader (not written in YAML).
    origin: str = Field("builtin", exclude=True)
    source_file: str | None = Field(None, exclude=True)

    # Compiled regexes (private, built after validation).
    _compiled: list[re.Pattern] = []
    _compiled_not: list[re.Pattern] = []

    @field_validator("id")
    @classmethod
    def _id(cls, v: str) -> str:
        if not RULE_ID_RE.match(v):
            raise ValueError(
                "id must be 3-120 chars of lowercase letters, digits, '.', '_' or '-' "
                "(e.g. 'acme.java.legacy-crypto')"
            )
        return v

    @field_validator("cwe", mode="before")
    @classmethod
    def _cwe(cls, v):
        if v in (None, ""):
            return None
        n = parse_cwe(v)
        if n is None:
            raise ValueError(f"invalid CWE {v!r}; use the form CWE-89")
        return cwe_label(n)

    @field_validator("languages", mode="before")
    @classmethod
    def _langs(cls, v):
        if isinstance(v, str):
            v = [v]
        aliases = {"js": "javascript", "node": "javascript", "py": "python"}
        return [aliases.get(str(x).lower(), str(x).lower()) for x in v]

    @field_validator("scope")
    @classmethod
    def _scope(cls, v: str) -> str:
        if v not in ("line", "file"):
            raise ValueError("scope must be 'line' or 'file'")
        return v

    @model_validator(mode="after")
    def _check(self) -> "Rule":
        if not self.name:
            self.name = self.id
        if self.type == RuleType.AI:
            if not self.instruction.strip():
                raise ValueError("type 'ai' rules need an `instruction`")
            if not self.cwe:
                raise ValueError("type 'ai' rules need a `cwe` so findings can be mapped to OWASP")
        else:
            if not self.patterns:
                raise ValueError(f"type '{self.type.value}' rules need at least one entry in `patterns`")
            if self.type != RuleType.PATTERN:
                # Taint markers never produce findings on their own.
                self.mode = RuleMode.HINT
            if self.type == RuleType.PATTERN and self.mode == RuleMode.REPORT and not self.cwe:
                raise ValueError("pattern rules in `report` mode need a `cwe`")
        flags = 0 if self.case_sensitive else re.IGNORECASE
        if self.scope == "file":
            flags |= re.MULTILINE
        compiled, compiled_not = [], []
        for p in self.patterns:
            try:
                compiled.append(re.compile(p, flags))
            except re.error as exc:
                raise ValueError(f"invalid regex in patterns: {p!r}: {exc}") from exc
        for p in self.pattern_not:
            try:
                compiled_not.append(re.compile(p, flags))
            except re.error as exc:
                raise ValueError(f"invalid regex in pattern-not: {p!r}: {exc}") from exc
        self._compiled = compiled
        self._compiled_not = compiled_not
        return self

    # Convenience accessors used by the engine.
    @property
    def regexes(self) -> list[re.Pattern]:
        return self._compiled

    @property
    def not_regexes(self) -> list[re.Pattern]:
        return self._compiled_not

    def summary(self) -> dict:
        """Compact JSON-able view for `argus rules list` and the web UI."""
        return {
            "id": self.id,
            "name": self.name,
            "type": self.type.value,
            "mode": self.mode.value if self.type != RuleType.AI else "ai",
            "languages": [lang.value for lang in self.languages],
            "cwe": self.cwe,
            "severity": self.severity.value,
            "origin": self.origin,
            "source_file": self.source_file,
            "enabled": self.enabled,
        }


class RuleFile(BaseModel):
    model_config = ConfigDict(extra="forbid")
    version: int = 1
    rules: list[dict] = Field(default_factory=list)
