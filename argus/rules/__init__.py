"""Detection rules: built-in packs plus user-defined custom rules (YAML)."""

from .engine import RuleEngine, Signal, is_suppressed, path_matches, suppressions
from .loader import (
    SCAFFOLDS,
    RuleLoadError,
    RuleSet,
    load_rules,
    parse_rule_data,
    parse_rule_file,
    save_custom_rule,
)
from .model import Rule, RuleMode, RuleType, Severity

__all__ = [
    "SCAFFOLDS",
    "Rule",
    "RuleEngine",
    "RuleLoadError",
    "RuleMode",
    "RuleSet",
    "RuleType",
    "Severity",
    "Signal",
    "is_suppressed",
    "load_rules",
    "parse_rule_data",
    "parse_rule_file",
    "path_matches",
    "save_custom_rule",
    "suppressions",
]
