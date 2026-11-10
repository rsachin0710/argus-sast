"""Structured outputs every agent must return.

Each model below is turned into a JSON schema and sent to the provider; the
reply is validated against it (see ``LLMClient.structured``). Closed
``Literal`` sets mean the model cannot invent verdicts, roles or impact
levels, which is a large part of what keeps results consistent.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field, field_validator


class ReconOutput(BaseModel):
    frameworks: list[str] = Field(default_factory=list, description="Web/app frameworks in use")
    entry_points: list[str] = Field(default_factory=list, description="Main ways untrusted input enters (routes, handlers, CLIs)")
    auth_model: str = Field("", description="How users authenticate and how authorization is enforced, if visible")
    global_protections: list[str] = Field(default_factory=list, description="Global middleware/filters that sanitise or protect (CSRF, CORS, ORM, escaping)")
    data_stores: list[str] = Field(default_factory=list)
    notes: str = ""

    @field_validator("frameworks", "entry_points", "global_protections", "data_stores")
    @classmethod
    def _cap(cls, v: list[str]) -> list[str]:
        return [str(x)[:200] for x in v[:20]]


class HunterFinding(BaseModel):
    line: int = Field(..., description="Absolute line number of the vulnerable operation (the sink)")
    end_line: int | None = Field(None, description="Last line of the vulnerable statement if it spans lines")
    evidence: str = Field(..., description="The code on `line`, copied exactly as shown (without the line-number prefix)")
    cwe: str = Field(..., description="Most specific CWE id from the checklist, e.g. CWE-89")
    title: str = Field(..., description="Short title, e.g. 'SQL injection via username parameter'")
    reason: str = Field(..., description="Why this is exploitable: where untrusted data comes from and how it reaches this line")
    source: str | None = Field(None, description="Where the untrusted data enters, e.g. 'line 26 @RequestParam username'")
    related_rule: str | None = Field(None, description="Rule id from the signals or custom checks this relates to, if any")


class HunterOutput(BaseModel):
    findings: list[HunterFinding] = Field(default_factory=list)

    @field_validator("findings")
    @classmethod
    def _cap(cls, v: list[HunterFinding]) -> list[HunterFinding]:
        return v[:25]


class FlowStepOut(BaseModel):
    file: str
    line: int
    role: Literal["source", "propagation", "sanitizer", "sink"]
    note: str = ""


class TracerArgs(BaseModel):
    """Arguments for the Tracer's tools. A typed model (not a free-form dict) so
    providers with strict structured outputs (additionalProperties: false) accept it."""

    path: str | None = Field(None, description="read_lines: file path as shown in the code header")
    start: int | None = Field(None, description="read_lines: first line")
    end: int | None = Field(None, description="read_lines: last line")
    name: str | None = Field(None, description="get_symbol / find_callers: function name")
    pattern: str | None = Field(None, description="search: Python regex")

    def used(self) -> dict:
        return self.model_dump(exclude_none=True)


class TracerAction(BaseModel):
    """One step of the Tracer's tool loop: either call a tool or finish."""

    action: Literal["read_lines", "get_symbol", "find_callers", "search", "final"]
    args: TracerArgs = Field(default_factory=TracerArgs, description="Tool arguments: read_lines{path,start,end} get_symbol{name} find_callers{name} search{pattern}")
    data_flow: list[FlowStepOut] = Field(default_factory=list, description="Only with action=final: ordered source -> sink steps")
    summary: str = Field("", description="Only with action=final: one paragraph describing the flow")
    sanitized: bool = Field(False, description="Only with action=final: true if a sanitizer/validation on the path makes it safe")


class SeverityFactorsOut(BaseModel):
    impact: Literal["rce", "data_breach", "privilege_escalation", "data_tamper", "dos", "info_leak", "minor"]
    attacker_position: Literal["remote_unauthenticated", "remote_authenticated", "internal", "local"]
    exploitability: Literal["easy", "moderate", "hard"]


class VerifierOutput(BaseModel):
    verdict: Literal["confirmed", "needs_context", "rejected"]
    confidence: float = Field(..., ge=0.0, le=1.0)
    title: str = Field(..., description="Final, specific title")
    cwe: str = Field(..., description="Most accurate CWE id, e.g. CWE-89")
    explanation: str = Field(..., description="Full reasoning: entry point, path to the sink, why existing controls do not stop it")
    exploit_scenario: str = Field("", description="Concrete attack, with an example payload where safe")
    impact: str = Field("", description="What the attacker gains / business impact")
    existing_controls: str = Field("", description="Controls considered and why they do or do not help")
    context_question: str | None = Field(None, description="Only for needs_context: ONE specific question the developer can answer")
    severity_factors: SeverityFactorsOut


class RemediatorOutput(BaseModel):
    start_line: int = Field(..., description="First line to replace (absolute)")
    end_line: int = Field(..., description="Last line to replace (absolute, inclusive)")
    fixed_code: str = Field(..., description="Exact replacement text for lines start_line..end_line, with correct indentation")
    new_imports: list[str] = Field(default_factory=list, description="Complete import lines to add at the top, if any")
    summary: str = Field(..., description="One or two sentences: what changed and why it is safe")
    notes: str = Field("", description="Anything the developer must do outside this snippet (config, rotation, tests)")
