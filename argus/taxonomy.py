"""OWASP Top 10 (2025 and 2021) and CWE taxonomy.

This module is DATA, not prompts: findings are mapped to OWASP categories by
looking their CWE up here, never by asking the model. That keeps the mapping
consistent run to run and stops a model from inventing categories.

Sources
-------
* OWASP Top 10:2025 "List of Mapped CWEs" for each category
  (https://top10.owasp.org/2025/), retrieved 2026-10-30.
* OWASP Top 10:2021 mapped CWE lists (https://owasp.org/Top10/).
* CWE names from MITRE (https://cwe.mitre.org).
"""

from __future__ import annotations

import re

OWASP_2025_NAMES = {
    "A01": "Broken Access Control",
    "A02": "Security Misconfiguration",
    "A03": "Software Supply Chain Failures",
    "A04": "Cryptographic Failures",
    "A05": "Injection",
    "A06": "Insecure Design",
    "A07": "Authentication Failures",
    "A08": "Software or Data Integrity Failures",
    "A09": "Security Logging & Alerting Failures",
    "A10": "Mishandling of Exceptional Conditions",
}

OWASP_2021_NAMES = {
    "A01": "Broken Access Control",
    "A02": "Cryptographic Failures",
    "A03": "Injection",
    "A04": "Insecure Design",
    "A05": "Security Misconfiguration",
    "A06": "Vulnerable and Outdated Components",
    "A07": "Identification and Authentication Failures",
    "A08": "Software and Data Integrity Failures",
    "A09": "Security Logging and Monitoring Failures",
    "A10": "Server-Side Request Forgery (SSRF)",
}

# Official 2025 mapped-CWE lists (A03 lists "447"; the category text names
# CWE-477 "Use of Obsolete Function", which is what we map).
OWASP_2025_CWES: dict[str, set[int]] = {
    "A01": {22, 23, 36, 59, 61, 65, 200, 201, 219, 276, 281, 282, 283, 284, 285, 352, 359, 377, 379,
            402, 424, 425, 441, 497, 538, 540, 548, 552, 566, 601, 615, 639, 668, 732, 749, 862, 863,
            918, 922, 1275},
    "A02": {5, 11, 13, 15, 16, 260, 315, 489, 526, 547, 611, 614, 776, 942, 1004, 1174},
    "A03": {477, 1035, 1104, 1329, 1357, 1395},
    "A04": {261, 296, 319, 320, 321, 322, 323, 324, 325, 326, 327, 328, 329, 330, 331, 332, 334, 335,
            336, 337, 338, 340, 342, 347, 523, 757, 759, 760, 780, 916, 1240, 1241},
    "A05": {20, 74, 76, 77, 78, 79, 80, 83, 86, 88, 89, 90, 91, 93, 94, 95, 96, 97, 98, 99, 103, 104,
            112, 113, 114, 115, 116, 129, 159, 470, 493, 500, 564, 610, 643, 644, 917},
    "A06": {73, 183, 256, 266, 269, 286, 311, 312, 313, 316, 362, 382, 419, 434, 436, 444, 451, 454,
            472, 501, 522, 525, 539, 598, 602, 628, 642, 646, 653, 656, 657, 676, 693, 799, 807, 841,
            1021, 1022, 1125},
    "A07": {258, 259, 287, 288, 289, 290, 291, 293, 294, 295, 297, 298, 299, 300, 302, 303, 304, 305,
            306, 307, 308, 309, 346, 350, 384, 521, 613, 620, 640, 798, 940, 941, 1390, 1391, 1392,
            1393},
    "A08": {345, 353, 426, 427, 494, 502, 506, 509, 565, 784, 829, 830, 915, 926},
    "A09": {117, 221, 223, 532, 778},
    "A10": {209, 215, 234, 235, 248, 252, 274, 280, 369, 390, 391, 394, 396, 397, 460, 476, 478, 484,
            550, 636, 703, 754, 755, 756},
}

OWASP_2021_CWES: dict[str, set[int]] = {
    "A01": {22, 23, 35, 59, 200, 201, 219, 264, 275, 276, 284, 285, 352, 359, 377, 402, 425, 441, 497,
            538, 540, 548, 552, 566, 601, 639, 651, 668, 706, 862, 863, 913, 922, 1275},
    "A02": {261, 296, 310, 319, 321, 322, 323, 324, 325, 326, 327, 328, 329, 330, 331, 335, 336, 337,
            338, 340, 347, 523, 720, 757, 759, 760, 780, 818, 916},
    "A03": {20, 74, 75, 77, 78, 79, 80, 83, 87, 88, 89, 90, 91, 93, 94, 95, 96, 97, 98, 99, 100, 113,
            116, 138, 184, 470, 471, 564, 610, 643, 644, 652, 917},
    "A04": {73, 183, 209, 213, 235, 256, 257, 266, 269, 280, 311, 312, 313, 316, 419, 430, 434, 444,
            451, 472, 501, 522, 525, 539, 579, 598, 602, 642, 646, 650, 653, 656, 657, 799, 807, 840,
            841, 927, 1021, 1173},
    "A05": {2, 11, 13, 15, 16, 260, 315, 520, 526, 537, 541, 547, 611, 614, 756, 776, 942, 1004, 1032,
            1174},
    "A06": {937, 1035, 1104},
    "A07": {255, 259, 287, 288, 290, 294, 295, 297, 300, 302, 304, 306, 307, 346, 384, 521, 613, 620,
            640, 798, 940, 1216},
    "A08": {345, 353, 426, 494, 502, 565, 784, 829, 830, 915},
    "A09": {117, 223, 532, 778},
    "A10": {918},
}

# Names for the CWEs Argus reasons about most. Unknown IDs still work; they
# simply show "CWE-<n>" as their name.
CWE_NAMES: dict[int, str] = {
    20: "Improper Input Validation",
    22: "Path Traversal",
    23: "Relative Path Traversal",
    36: "Absolute Path Traversal",
    59: "Link Following",
    73: "External Control of File Name or Path",
    74: "Injection",
    77: "Command Injection",
    78: "OS Command Injection",
    79: "Cross-site Scripting (XSS)",
    80: "Basic XSS",
    88: "Argument Injection",
    89: "SQL Injection",
    90: "LDAP Injection",
    91: "XML Injection",
    93: "CRLF Injection",
    94: "Code Injection",
    95: "Eval Injection",
    113: "HTTP Response Splitting",
    116: "Improper Encoding or Escaping of Output",
    117: "Improper Output Neutralization for Logs",
    200: "Exposure of Sensitive Information to an Unauthorized Actor",
    209: "Error Message Containing Sensitive Information",
    215: "Sensitive Information in Debugging Code",
    248: "Uncaught Exception",
    252: "Unchecked Return Value",
    256: "Unprotected Storage of Credentials",
    259: "Use of Hard-coded Password",
    260: "Password in Configuration File",
    269: "Improper Privilege Management",
    276: "Incorrect Default Permissions",
    284: "Improper Access Control",
    285: "Improper Authorization",
    287: "Improper Authentication",
    295: "Improper Certificate Validation",
    306: "Missing Authentication for Critical Function",
    307: "Improper Restriction of Excessive Authentication Attempts",
    311: "Missing Encryption of Sensitive Data",
    312: "Cleartext Storage of Sensitive Information",
    315: "Cleartext Storage of Sensitive Information in a Cookie",
    319: "Cleartext Transmission of Sensitive Information",
    321: "Use of Hard-coded Cryptographic Key",
    326: "Inadequate Encryption Strength",
    327: "Use of a Broken or Risky Cryptographic Algorithm",
    328: "Use of Weak Hash",
    329: "Not Using a Random IV with CBC Mode",
    330: "Use of Insufficiently Random Values",
    338: "Use of Cryptographically Weak PRNG",
    345: "Insufficient Verification of Data Authenticity",
    346: "Origin Validation Error",
    347: "Improper Verification of Cryptographic Signature",
    352: "Cross-Site Request Forgery (CSRF)",
    359: "Exposure of Private Personal Information",
    362: "Race Condition",
    377: "Insecure Temporary File",
    384: "Session Fixation",
    390: "Detection of Error Condition Without Action",
    396: "Declaration of Catch for Generic Exception",
    400: "Uncontrolled Resource Consumption",
    425: "Direct Request (Forced Browsing)",
    434: "Unrestricted Upload of File with Dangerous Type",
    470: "Unsafe Reflection",
    476: "NULL Pointer Dereference",
    477: "Use of Obsolete Function",
    489: "Active Debug Code",
    494: "Download of Code Without Integrity Check",
    501: "Trust Boundary Violation",
    502: "Deserialization of Untrusted Data",
    521: "Weak Password Requirements",
    522: "Insufficiently Protected Credentials",
    532: "Insertion of Sensitive Information into Log File",
    540: "Inclusion of Sensitive Information in Source Code",
    547: "Use of Hard-coded, Security-relevant Constants",
    550: "Server-generated Error Message Containing Sensitive Information",
    564: "SQL Injection: Hibernate",
    565: "Reliance on Cookies without Validation and Integrity Checking",
    566: "Authorization Bypass Through User-Controlled SQL Primary Key",
    598: "Use of GET Request Method With Sensitive Query Strings",
    601: "Open Redirect",
    602: "Client-Side Enforcement of Server-Side Security",
    611: "XML External Entity (XXE)",
    613: "Insufficient Session Expiration",
    614: "Sensitive Cookie Without 'Secure' Attribute",
    636: "Not Failing Securely ('Failing Open')",
    639: "Authorization Bypass Through User-Controlled Key (IDOR)",
    643: "XPath Injection",
    676: "Use of Potentially Dangerous Function",
    703: "Improper Check or Handling of Exceptional Conditions",
    732: "Incorrect Permission Assignment for Critical Resource",
    754: "Improper Check for Unusual or Exceptional Conditions",
    755: "Improper Handling of Exceptional Conditions",
    759: "Use of a One-Way Hash without a Salt",
    770: "Allocation of Resources Without Limits or Throttling",
    776: "XML Entity Expansion",
    778: "Insufficient Logging",
    798: "Use of Hard-coded Credentials",
    799: "Improper Control of Interaction Frequency",
    807: "Reliance on Untrusted Inputs in a Security Decision",
    829: "Inclusion of Functionality from Untrusted Control Sphere",
    830: "Inclusion of Web Functionality from an Untrusted Source",
    862: "Missing Authorization",
    863: "Incorrect Authorization",
    915: "Improperly Controlled Modification of Dynamically-Determined Object Attributes",
    916: "Use of Password Hash With Insufficient Computational Effort",
    917: "Expression Language Injection",
    918: "Server-Side Request Forgery (SSRF)",
    922: "Insecure Storage of Sensitive Information",
    942: "Permissive Cross-domain Policy with Untrusted Domains",
    943: "NoSQL / Data Query Logic Injection",
    1004: "Sensitive Cookie Without 'HttpOnly' Flag",
    1021: "Improper Restriction of Rendered UI Layers or Frames",
    1104: "Use of Unmaintained Third Party Components",
    1275: "Sensitive Cookie with Improper SameSite Attribute",
    1321: "Prototype Pollution",
    1333: "Inefficient Regular Expression Complexity (ReDoS)",
    1336: "Server-Side Template Injection",
    1357: "Reliance on Insufficiently Trustworthy Component",
    1395: "Dependency on Vulnerable Third-Party Component",
    1427: "Improper Neutralization of Input Used for LLM Prompting",
}

# What each hunter is told to look for, per OWASP 2025 category. These are the
# code-detectable CWEs plus a one-line "detection card" hint. Users extend the
# hunt with their own `type: ai` rules (see argus/rules).
FOCUS_CWES: dict[str, list[tuple[int, str]]] = {
    "A01": [
        (22, "file paths built from request data without canonicalising and checking the base dir"),
        (639, "object fetched by a user-supplied id without checking it belongs to the caller (IDOR)"),
        (862, "state-changing or sensitive endpoint with no authorization check"),
        (863, "authorization check that is wrong, client-controlled or bypassable"),
        (352, "cookie-authenticated state change with CSRF protection disabled or missing"),
        (601, "redirect target taken from request data without an allowlist"),
        (918, "server makes an HTTP request to a URL/host influenced by the user (SSRF)"),
        (200, "sensitive data (secrets, PII, internals) returned to callers who should not see it"),
        (732, "files or resources created world-readable/writable"),
    ],
    "A02": [
        (611, "XML parser with external entities / DTDs enabled (XXE)"),
        (489, "debug mode or debug endpoints enabled in production code"),
        (942, "CORS allowing any origin, especially with credentials"),
        (614, "session/auth cookie without Secure"),
        (1004, "session/auth cookie without HttpOnly"),
        (16, "insecure security-relevant configuration (e.g. disabled security headers)"),
    ],
    "A03": [
        (1104, "code depends on an obviously unmaintained or abandoned component"),
        (1357, "code loads or trusts a component from an untrusted source"),
        (477, "use of obsolete/deprecated security-relevant functions"),
    ],
    "A04": [
        (327, "broken or risky algorithm: DES, 3DES, RC4, ECB mode"),
        (328, "weak hash (MD5/SHA-1) used for passwords, signatures or integrity"),
        (916, "passwords hashed without bcrypt/scrypt/argon2/PBKDF2"),
        (330, "non-cryptographic RNG used for tokens, ids, passwords or keys"),
        (321, "hard-coded cryptographic key or IV"),
        (329, "static or predictable IV"),
        (319, "sensitive data sent over plain HTTP"),
        (347, "signature/JWT not verified, or 'none' algorithm accepted"),
    ],
    "A05": [
        (89, "SQL built by string concatenation/formatting with untrusted data"),
        (78, "OS command built from untrusted data or run through a shell"),
        (79, "untrusted data written into HTML/DOM without context-aware encoding"),
        (94, "eval/exec/Function/script engine on untrusted data"),
        (917, "expression language / SpEL / OGNL evaluated on untrusted data"),
        (90, "LDAP filter built from untrusted data"),
        (643, "XPath built from untrusted data"),
        (113, "untrusted data in HTTP response headers"),
        (470, "class/method chosen by untrusted input (unsafe reflection)"),
        (20, "missing validation where it directly enables an injection"),
    ],
    "A06": [
        (434, "file upload without type/size/name validation, stored in a served location"),
        (602, "security decision enforced only on the client"),
        (799, "no rate limiting on login, OTP, password reset or other abuse-prone flows"),
        (807, "security decision based on a client-controlled value (header, cookie, hidden field)"),
        (256, "credentials stored in plaintext"),
        (362, "race condition on a security-relevant check (TOCTOU)"),
    ],
    "A07": [
        (798, "hard-coded password, API key or token"),
        (287, "authentication that can be bypassed or is implemented incorrectly"),
        (306, "critical function reachable without authentication"),
        (307, "no lockout or throttling on authentication attempts"),
        (384, "session id not rotated after login (session fixation)"),
        (295, "TLS certificate validation disabled"),
        (613, "sessions/tokens that never expire"),
        (521, "weak password policy enforced in code"),
    ],
    "A08": [
        (502, "deserialization of untrusted data (ObjectInputStream, pickle, yaml.load, node-serialize)"),
        (915, "mass assignment: request body bound directly onto a model/entity"),
        (494, "code or plugins downloaded and run without an integrity check"),
        (829, "loading scripts/modules from an untrusted, user-controlled location"),
        (345, "trusting data whose authenticity is not verified"),
    ],
    "A09": [
        (532, "passwords, tokens or PII written to logs"),
        (117, "untrusted data written to logs without neutralising CR/LF"),
        (778, "security events (login failure, access denied) not logged"),
    ],
    "A10": [
        (209, "stack traces or exception details returned to the client"),
        (636, "security check that fails open when an exception occurs"),
        (390, "error swallowed by an empty or ignore-all catch in security-relevant code"),
        (755, "exceptional conditions handled in a way that leaves an insecure state"),
        (476, "null dereference reachable from untrusted input"),
    ],
}

# How hunters are grouped in "specialist" mode (one agent per group).
HUNTER_GROUPS: dict[str, list[str]] = {
    "access-control": ["A01"],
    "injection": ["A05"],
    "crypto": ["A04"],
    "config-and-integrity": ["A02", "A03", "A08"],
    "authentication": ["A07"],
    "design-errors-logging": ["A06", "A09", "A10"],
}

_CWE_RE = re.compile(r"^\s*(?:CWE)?[-_ ]?(\d{1,5})\s*$", re.IGNORECASE)


def parse_cwe(value: str | int | None) -> int | None:
    """'CWE-89', 'cwe 89', '89', 89 -> 89. Returns None if not a CWE id."""
    if value is None:
        return None
    if isinstance(value, int):
        return value if value > 0 else None
    m = _CWE_RE.match(str(value))
    return int(m.group(1)) if m else None


def cwe_label(cwe: int | None) -> str:
    return f"CWE-{cwe}" if cwe else "CWE-unknown"


def cwe_name(cwe: int | None) -> str:
    if cwe is None:
        return "Unknown weakness"
    return CWE_NAMES.get(cwe, f"CWE-{cwe}")


def owasp_for(cwe: int | None) -> dict[str, str | None]:
    """Map a CWE to its OWASP 2025 and 2021 category IDs (None if unmapped)."""
    out: dict[str, str | None] = {"2025": None, "2021": None}
    if cwe is None:
        return out
    for cat, cwes in OWASP_2025_CWES.items():
        if cwe in cwes:
            out["2025"] = cat
            break
    for cat, cwes in OWASP_2021_CWES.items():
        if cwe in cwes:
            out["2021"] = cat
            break
    return out


def is_known_cwe(cwe: int | None) -> bool:
    if cwe is None:
        return False
    if cwe in CWE_NAMES:
        return True
    return any(cwe in s for s in OWASP_2025_CWES.values()) or any(
        cwe in s for s in OWASP_2021_CWES.values()
    )


def owasp_label(cat: str | None, edition: str = "2025") -> str:
    if not cat:
        return "Not in OWASP Top 10"
    names = OWASP_2025_NAMES if edition == "2025" else OWASP_2021_NAMES
    return f"{cat}:{edition} {names.get(cat, '')}".strip()


def categories_to_2025(categories: list[str], edition: str) -> list[str]:
    """Translate user-selected categories to 2025 IDs (hunters are organised by
    2025). For a 2021 selection we include every 2025 category that shares a CWE."""
    if not categories:
        return list(OWASP_2025_NAMES)
    if edition == "2025":
        return categories
    wanted: set[str] = set()
    for c in categories:
        cwes = OWASP_2021_CWES.get(c, set())
        for cat25, cwes25 in OWASP_2025_CWES.items():
            if cwes & cwes25:
                wanted.add(cat25)
        if c == "A10":
            wanted.add("A01")  # SSRF moved into A01:2025
    return sorted(wanted) or list(OWASP_2025_NAMES)


def mitre_url(cwe: int | None) -> str | None:
    return f"https://cwe.mitre.org/data/definitions/{cwe}.html" if cwe else None
