# Prioritised Security Findings

This assessment synthesizes automated scan results across SAST (Bandit), SCA (pip-audit), Container Scanning (Trivy), and IaC Scanning (Checkov) with manual code review of the VulnTracker prototype.

| ID | Title | Detection Method | Severity | Scope | Business Impact |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **SEC-01** | SQL Injection via String Interpolation | Manual Review | Critical | Starter Code (`app/database.py`) | Allows arbitrary SQL execution via the search endpoint. Attackers can bypass tenant boundaries, dump the full database, or tamper with findings. |
| **SEC-02** | JWT Algorithm Confusion (`alg: none`) | Manual Review | Critical | Starter Code (`app/auth.py`) | The token decoder explicitly accepted unsigned tokens (`alg: "none"`), allowing attackers to forge arbitrary user and admin sessions without knowing the secret key. |
| **SEC-03** | Insecure Direct Object Reference (IDOR) | Manual Review | High | Starter Code (`app/main.py`) | The `GET /scans/{scan_id}` endpoint lacked ownership checks (`owner_id == current_user.id`), exposing all confidential vulnerability records across teams. |
| **SEC-04** | Plaintext Password Exposure in Logs | Manual / SAST | High | Starter Code (`app/main.py`) | User passwords were logged in cleartext during login attempts, creating exposure risks through log aggregators and terminal history. |
| **SEC-05** | Rate Limiting Absence on Share Links | Manual Review | Medium | New Feature (`app/main.py`) | Password-protected share links do not throttle repeated incorrect attempts, allowing high-speed brute-force attacks against report passwords. |
| **SEC-06** | Hardcoded Secrets and Insecure Defaults | SAST / Manual | High | Starter Code (`app/config.py`) | Application secrets, JWT signing keys, and service tokens are committed in source code instead of supplied via environment variables or secret vaults. |
| **SEC-07** | Known Vulnerabilities in Outdated Packages | SCA (pip-audit) | High | Dependencies (`requirements.txt`) | Unpinned dependencies expose the runtime to known public CVEs. |
| **SEC-08** | Insecure Container Capabilities & Writable Root FS | IaC (Checkov) | Medium | Infrastructure (`helm/`) | Missing default read-only root filesystems and elevated Linux capabilities allow potential post-exploitation modification inside container environments. |
| **SEC-09** | Unauthenticated Webhook Dispatch & SSRF Risk | Manual Review | Medium | Starter Code (`notify/src/index.js`) | The background notification service accepts arbitrary payloads without authentication, creating potential Server-Side Request Forgery (SSRF) vectors. |
