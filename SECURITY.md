# Security policy

Argus reads untrusted code and can edit files after user consent, so we take reports seriously.

Please report vulnerabilities privately through GitHub's "Report a vulnerability" (Security tab of this
repository) rather than in a public issue. Include the Argus version, steps to reproduce and the impact.

In scope, for example:
- prompt injection that makes Argus apply a change, read files outside the scan root, or send data to an
  unexpected endpoint;
- bypasses of the web UI token, Host, CSRF or Origin checks;
- any way to change scanned code without the per-finding confirmation;
- secrets reaching an LLM provider or a report despite redaction.

Out of scope: missed vulnerabilities or false positives in scanned code (please open a normal issue with
a minimal example, which helps improve the rules and prompts).
