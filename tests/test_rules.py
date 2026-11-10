"""Rules engine and custom rules."""

from pathlib import Path

from argus.config import Language, load_settings, user_rules_dir
from argus.rules import RuleEngine, load_rules, parse_rule_data, save_custom_rule, suppressions
from argus.rules.engine import is_suppressed

ROOT = Path(__file__).resolve().parent.parent


def test_builtin_rules_load_cleanly():
    rs = load_rules(load_settings())
    assert rs.errors == []
    assert len(rs.rules) > 80
    assert {r.origin for r in rs.rules.values()} == {"builtin"}


def test_custom_rule_validation_errors_are_reported_not_raised():
    raw = {"rules": [
        {"id": "Bad ID!", "patterns": ["x"], "cwe": "CWE-1"},
        {"id": "acme.no-cwe", "patterns": ["x"]},                   # report mode needs a CWE
        {"id": "acme.bad-regex", "patterns": ["(unclosed"], "cwe": "CWE-89"},
        {"id": "acme.ai-no-instruction", "type": "ai", "cwe": "CWE-639"},
        {"id": "acme.ok", "patterns": ["foo\\("], "cwe": "CWE-89"},
    ]}
    rules, errors = parse_rule_data(raw, "test.yaml", "user")
    assert [r.id for r in rules] == ["acme.ok"]
    assert len(errors) == 4
    assert any("invalid regex" in e.message for e in errors)


def test_example_custom_rules_file_is_valid():
    rs = load_rules(load_settings(), [ROOT / "examples" / "rules" / "acme-rules.yaml"])
    assert rs.errors == []
    types = {r.type.value for r in rs.rules.values() if r.origin == "cli"}
    assert types == {"pattern", "ai", "sink", "source", "sanitizer"}


def test_custom_rule_detects_and_respects_pattern_not():
    rules, _ = parse_rule_data({"rules": [{
        "id": "acme.java.legacy", "languages": ["java"], "cwe": "CWE-327", "severity": "high",
        "patterns": [r"LegacyCrypto\.encrypt\("], "pattern-not": [r"approved"],
    }]}, "t", "user")
    from argus.rules.loader import RuleSet

    eng = RuleEngine(RuleSet(rules={r.id: r for r in rules}))
    lines = ["x = LegacyCrypto.encrypt(data);", "y = LegacyCrypto.encrypt(d); // approved", "// LegacyCrypto.encrypt( in a comment"]
    hits = eng.scan_file("A.java", Language.JAVA, lines)
    assert [h.line for h in hits] == [1]


def test_file_scope_rule_xxe():
    rs = load_rules(load_settings())
    eng = RuleEngine(rs)
    vulnerable = ["DocumentBuilderFactory f = DocumentBuilderFactory.newInstance();"]
    hardened = vulnerable + ['f.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);']
    ids = lambda lines: {s.rule_id for s in eng.scan_file("X.java", Language.JAVA, lines)}
    assert "argus.java.xxe.parser" in ids(vulnerable)
    assert "argus.java.xxe.parser" not in ids(hardened)


def test_user_rules_dir_is_always_loaded_and_can_override_builtin():
    save_custom_rule({"id": "argus.python.code.eval", "languages": ["python"], "cwe": "CWE-95",
                      "severity": "low", "patterns": [r"\beval\("], "message": "overridden"})
    assert (user_rules_dir() / "argus.python.code.eval.yaml").is_file()
    rs = load_rules(load_settings())
    r = rs.get("argus.python.code.eval")
    assert r.origin == "user" and r.severity.value == "low"
    assert "argus.python.code.eval" in rs.overridden


def test_disable_list(monkeypatch):
    from argus.config import save_user_settings

    s = load_settings()
    s.rules.disable = ["argus.python.code.eval"]
    save_user_settings(s)
    rs = load_rules(load_settings())
    assert not rs.get("argus.python.code.eval").enabled


def test_project_rules_need_opt_in(tmp_path):
    proj = tmp_path / "proj"
    (proj / ".argus" / "rules").mkdir(parents=True)
    (proj / ".argus" / "rules" / "r.yaml").write_text(
        "rules:\n  - id: proj.rule\n    cwe: CWE-89\n    patterns: ['x']\n")
    assert load_rules(load_settings(), target_root=proj).get("proj.rule") is None
    s = load_settings({"scan": {"load_project_rules": True}})
    assert load_rules(s, target_root=proj).get("proj.rule") is not None


def test_inline_suppressions():
    lines = ["a = eval(x)  # argus-ignore[CWE-95]", "# argus-ignore", "b = eval(y)", "c = eval(z)"]
    supp = suppressions(lines)
    assert is_suppressed(supp, 1, "CWE-95", None)
    assert not is_suppressed(supp, 1, "CWE-89", None)
    assert is_suppressed(supp, 3, "CWE-95", None)
    assert not is_suppressed(supp, 4, "CWE-95", None)
