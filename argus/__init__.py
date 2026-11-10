"""Argus — an open-source, AI-agent powered SAST scanner.

Argus finds OWASP Top 10 / CWE-mapped vulnerabilities in Java, Python and
JavaScript code. Deterministic code (parsing, rule matching, line checks,
severity scoring) does everything it can; LLM agents do the reasoning that
needs judgement (is this exploitable? how does data reach the sink? what is
the secure fix?).

High-level flow (see ``argus.pipeline.ScanService`` for the full version):

    target  ->  index (tree-sitter)  ->  rules (built-in + custom)
            ->  Recon agent  ->  Hunter agents (voted)  ->  line verification
            ->  Tracer agent  ->  Verifier agent  ->  Remediator agent
            ->  reports (JSON / TXT / SARIF / MD)  +  patches (never applied
                without explicit user consent, see ``argus.fixer``)
"""

__version__ = "0.1.0"

# Bumped whenever a prompt template changes so cached LLM responses and
# reported findings can be traced back to the exact prompt that made them.
PROMPT_VERSION = "2026.11.1"
