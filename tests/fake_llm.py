"""A scripted, deterministic stand-in for an LLM provider (tests only).

It reads the same prompts a real model would get and answers like a
well-behaved model, so the whole agent pipeline (recon, hunters + voting,
line verification, tracer tool loop, verifier verdicts, remediation patches)
can be tested offline. It is NOT selectable from config: the provider enum
stays limited to the four real vendors.
"""

from __future__ import annotations

import json
import re

from argus.config import LLMSettings, ProviderName
from argus.llm.base import LLMProvider, LLMResult

_LINE = re.compile(r"^\s*(\d+) \| (.*)$")

# (regex on a code line, CWE, title)
SINKS = [
    (r"executeQuery\(\".*\+", "CWE-89", "SQL injection in user search"),
    (r"cur\.execute\(f\"", "CWE-89", "SQL injection via f-string"),
    (r"pool\.query\(`", "CWE-89", "SQL injection via template literal"),
    (r"Runtime\.getRuntime\(\)\.exec\(", "CWE-78", "OS command injection in ping"),
    (r"new File\(\"/var/app/avatars/\" \+", "CWE-22", "Path traversal in avatar download"),
    (r"response\.sendRedirect\(next\)", "CWE-601", "Open redirect"),
    (r"requests\.get\(url", "CWE-918", "SSRF in fetch endpoint"),
    (r"subprocess\.check_output\(", "CWE-78", "Command injection via shell=True"),
]


class FakeProvider(LLMProvider):
    name = ProviderName.OLLAMA  # any enum member; it never makes HTTP calls

    def __init__(self, drop_on_vote: int | None = None, hallucinate: bool = True):
        super().__init__(LLMSettings(provider="ollama", model="fake"), None)
        self.calls: list[str] = []
        self.drop_on_vote = drop_on_vote
        self.hallucinate = hallucinate
        self._hunter_calls: dict[str, int] = {}

    async def complete(self, system, messages, schema=None):
        user = messages[-1]["content"]
        role = re.search(r"You are (?:the |a )?(\w+) agent", system)
        role = role.group(1) if role else "?"
        self.calls.append(role)
        data = getattr(self, f"_{role.lower()}")(user, messages)
        return LLMResult(text=json.dumps(data), data=data, input_tokens=100, output_tokens=50)

    # --- agents ---------------------------------------------------------------
    def _recon(self, user, messages):
        return {"frameworks": ["Spring Boot", "Flask", "Express"], "entry_points": ["HTTP routes"],
                "auth_model": "none visible", "global_protections": [], "data_stores": ["SQL"], "notes": ""}

    def _hunter(self, user, messages):
        path = re.search(r"^File: (\S+)", user, re.M).group(1)
        rng = re.search(r"find exploitable security vulnerabilities in lines (\d+)-(\d+)", user)
        lo, hi = int(rng.group(1)), int(rng.group(2))
        key = f"{path}:{lo}"
        vote = self._hunter_calls.get(key, 0)
        self._hunter_calls[key] = vote + 1
        out = []
        for ln in user.splitlines():
            m = _LINE.match(ln)
            if not m:
                continue
            n, code = int(m.group(1)), m.group(2)
            if not (lo <= n <= hi):
                continue
            for rx, cwe, title in SINKS:
                if re.search(rx, code):
                    if self.drop_on_vote is not None and vote == self.drop_on_vote and cwe == "CWE-601":
                        continue  # one vote misses it: majority voting must keep it
                    out.append({"line": n, "evidence": code.strip(), "cwe": cwe, "title": title,
                                "reason": "request data reaches this call unsanitised"})
        if self.hallucinate and out:
            out.append({"line": out[0]["line"] + 1, "evidence": "this code does not exist anywhere()",
                        "cwe": "CWE-79", "title": "Hallucinated", "reason": "made up"})
        return {"findings": out}

    def _tracer(self, user, messages):
        if len(messages) == 1:  # first step: use a tool
            path = re.search(r"at (\S+):(\d+)", user)
            return {"action": "read_lines", "args": {"path": path.group(1), "start": 1, "end": 5}}
        m = re.search(r"Candidate: .* at (\S+):(\d+)", messages[0]["content"])
        return {"action": "final", "data_flow": [
            {"file": m.group(1), "line": int(m.group(2)), "role": "sink", "note": "dangerous call"},
            {"file": m.group(1), "line": 99999, "role": "source", "note": "bogus line, must be dropped"},
        ], "summary": "request parameter flows to the sink", "sanitized": False}

    def _verifier(self, user, messages):
        n = int(re.search(r"the flagged line is (\d+)", user).group(1))
        flagged = next((ln for ln in user.splitlines() if re.match(rf"^\s*{n} \| ", ln)), "")
        if "requests.get(url" in flagged and "answered a previous question" not in user:
            return {"verdict": "needs_context", "confidence": 0.6, "title": "Possible SSRF in /fetch",
                    "cwe": "CWE-918", "explanation": "url comes from the query string.",
                    "context_question": "Is /fetch reachable from the internet or only internally?",
                    "severity_factors": {"impact": "data_breach", "attacker_position": "remote_unauthenticated",
                                         "exploitability": "easy"}}
        if "Weak hash" in user and "MessageDigest" in flagged:
            return {"verdict": "rejected", "confidence": 0.7, "title": "MD5 not used for security", "cwe": "CWE-328",
                    "explanation": "checksum only", "severity_factors": {"impact": "minor",
                    "attacker_position": "local", "exploitability": "hard"}}
        title = re.search(r"- Title: (.*)", user).group(1)
        return {"verdict": "confirmed", "confidence": 0.9, "title": title, "cwe": re.search(r"- CWE: (CWE-\d+)", user).group(1),
                "explanation": "Untrusted input reaches the sink without validation.",
                "exploit_scenario": "send a crafted parameter", "impact": "data exposure",
                "severity_factors": {"impact": "data_breach", "attacker_position": "remote_unauthenticated",
                                     "exploitability": "easy"}}

    def _remediator(self, user, messages):
        line = int(re.search(r"at \S+:(\d+)\n", user).group(1))
        code = {int(m.group(1)): m.group(2) for m in map(_LINE.match, user.splitlines()) if m}
        original = code[line]
        lang = re.search(r"language: (\w+)", user).group(1)
        if "cur.execute(f\"" in original:
            fixed = original.replace("cur.execute(f\"SELECT * FROM users WHERE name = '{name}'\")",
                                     "cur.execute(\"SELECT * FROM users WHERE name = ?\", (name,))")
        else:
            fixed = original + ("  # argus: validated" if lang == "python" else "  // argus: validated")
        return {"start_line": line, "end_line": line, "fixed_code": fixed, "new_imports": [],
                "summary": "Use parameters / validate input."}
