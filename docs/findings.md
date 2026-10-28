# Prioritised Security Findings

This assessment combines four automated scans — SAST (Bandit), dependency
analysis (pip-audit and npm audit), container image scanning (Trivy) and IaC
scanning (Checkov) — with manual review of the VulnTracker prototype.

Severities below are my own assessment for this application, not the severity
the tool printed. Two of them differ from the tool's rating in opposite
directions, and I have explained why in each case.

| ID | Title | Detection | Severity | Scope | Business impact |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **SEC-01** | SQL injection in scan search | Bandit B608 + manual | Critical | Starter (`app/database.py`) | I ran a `UNION SELECT` through `/scans/search` and got back `users.username`, `users.email` and the bcrypt password hashes of other accounts. SQLite does not allow stacked statements through this call, so the vector is read-only — an attacker cannot alter findings this way. That still means the credentials of the security team using this tool are recoverable through a normal API call, and from there their passwords are crackable offline. |
| **SEC-06** | Five credentials committed to source | Bandit B105 + manual | Critical | Starter (`app/config.py`, `notify/src/config.js`) | The JWT signing key, database password, admin API key and the notify service key were all literals in source. The signing key is the serious one: holding it means minting a valid token for any user, with no password and no login record. Bandit rated this LOW because it scores the pattern — a string literal — not the consequence. I rate it Critical. All five are still in git history, so they need rotating, not just deleting. |
| **SEC-03** | Missing ownership check on scan read | Manual | High | Starter (`app/main.py`) | `GET /scans/{scan_id}` filtered on id alone while `PATCH` and `DELETE` filtered on owner. Any registered user could read any other tenant's findings by incrementing a number, and registration is open. No scanner reported this: the code is syntactically correct, it is a missing business rule. |
| **SEC-10** | Search ignored record ownership | Manual | High | Starter (`app/database.py`) | Separate from SEC-01. The search statement had no `owner_id` predicate, so `?q=cve` returned every tenant's findings with no injection payload at all. I confirmed it with two accounts before fixing it: the second user searching for the first user's finding got it back. Two independent routes to the same cross-tenant exposure suggests the ownership rule was never written down in one place. |
| **SEC-04** | Passwords written to logs in plaintext | Manual | High | Starter (`app/main.py`) | Every login attempt logged the submitted password, successful or not. Logs are typically readable by more people than the database and are retained for months, so this quietly turns log access into account takeover. Bandit did not catch this; it has no rule for it. |
| **SEC-09** | Unauthenticated webhook registration and SSRF | Manual | High | Starter (`notify/`) | Two problems compound. Anyone who can reach the service registers any URL, and `dispatcher.js` attaches `X-Service-Key` to every dispatch — so an attacker who registers their own endpoint is handed the internal service key. Registering `http://169.254.169.254/` reaches cloud instance metadata, and the retry and timeout behaviour works as an internal port scanner. |
| **SEC-07** | Dependencies pinned to vulnerable versions | pip-audit, npm audit | High | `requirements.txt`, `notify/package-lock.json` | The pins are exact, which is correct — but they point at old releases. pip-audit reports 67 advisories across 8 packages; npm audit reports 11 more including one critical (`proxy-addr`). I prioritised these by reachability rather than count. `python-jose` CVE-2024-33663 matters because every request verifies a token with it. `axios` 0.21.1's absolute-URL SSRF matters because SEC-09 lets an attacker choose the URL it fetches. The 16 `python-multipart` advisories do not matter here, because nothing in this service parses multipart data. |
| **SEC-14** | Container base image carries 18 critical CVEs | Trivy | Medium | `Dockerfile` | Scanning the built image returns 18 critical and 148 high findings, all inherited from `python:3.11.8-slim-bookworm` (Debian 12.5) rather than from our code. Rated Medium, not Critical: these sit in OS utilities a FastAPI process never invokes, so they are reachable only by an attacker who already has execution inside the container. They would worsen an incident rather than cause one. The fix is a newer base image, not a code change. |
| **SEC-02** | Unsigned algorithm accepted in JWT decode | Manual | Medium | Starter (`app/auth.py`) | `decode_token` listed `"none"` among accepted algorithms, which reads like a total authentication bypass. I tested it rather than assuming: python-jose rejects the forged token because it cannot construct a key for `none`, so it is not a bypass. What it did do is raise `JWKError`, which the handler did not catch — it caught only `JWTError` — so a forged token returned HTTP 500 with a full traceback. So the real issue is unauthenticated information disclosure, not identity forgery. Downgraded to Medium on that evidence, and removed from the code regardless. |
| **SEC-11** | Reflective CORS with credentials | Manual | Medium | Starter (`app/main.py`) | The middleware echoed any inbound `Origin` back with `Access-Control-Allow-Credentials: true`, which tells the browser every site on the internet is a trusted origin. I rated this Medium rather than High on purpose: this API authenticates with a bearer token in a header, not a cookie, so a malicious site has no ambient session to ride, and the middleware ran after `call_next` so there was no preflight responder either. It becomes Critical the day anyone introduces cookie auth. |
| **SEC-12** | Tracebacks returned in 500 responses | Manual | Medium | Starter (`app/main.py`, `notify/src/index.js`) | The handler returned the exception text, its type and a full traceback; the notify service returned `err.stack`. This mattered mostly as an amplifier — it echoed the failing SQL statement straight back, which is the difference between SEC-01 needing hundreds of requests and needing one. |
| **SEC-05** | No throttling on shared report links | Manual | Medium | New feature (`app/main.py`) | Found reviewing my own Task 1 code. A password-protected share link accepted unlimited guesses, so the password protecting a confidential report could be brute-forced at network speed. |
| **SEC-13** | No rate limiting or password policy on auth | Manual | Medium | Starter (`app/main.py`) | Neither `/auth/login` nor `/auth/register` throttles attempts, and there is no minimum password strength — the starter tests register accounts with the password `pw`. Unlimited guessing against a two-character password on a security analyst's account is a realistic way in. |
| **SEC-08** | Writable container root filesystem | Checkov CKV_K8S_22 | Medium | `helm/` | The chart ran with a writable root filesystem, which lets an attacker who achieves execution drop tooling or modify application files in place. Checkov also flags elevated capabilities as a general class, but that half did not apply here — the chart already dropped all capabilities. |

Checkov reported 7 failed checks against 83 passed. Beyond SEC-08, the
remaining ones (default namespace, image pull policy, image digest, service
account token mounting, missing NetworkPolicy) are hardening gaps rather than
vulnerabilities; the NetworkPolicy and read-only filesystem are now addressed
and the rest are recorded in the remediation plan.

---

## Verified false positives

Dismissing a finding needs the same evidence as raising one.

| Finding | Verdict | Why |
| :--- | :--- | :--- |
| Bandit B105 `hardcoded_password_string` at `app/main.py:158` | False positive | The matched literal is `'bearer'` — the OAuth 2.0 token type in the login response body, not a credential. The rule fires on any string assigned near a password-like identifier. |
| Bandit severity on the `app/config.py` secrets (rated LOW) | Under-rated by the tool | Recorded above as SEC-06 at Critical. Bandit scores the presence of a literal, not what the literal does. This one signs every authentication token. |

## A note on what the tools did and did not find

Worth recording, since tool choice was part of the exercise:

Bandit found the SQL injection and the hardcoded secrets with precise line
numbers, which is good value for a free tool. It found neither authorization
failure — SEC-03 and SEC-10 — and those are the two that break tenant
isolation. Both are well-formed code missing a rule about who may see what,
which is not something pattern matching can detect.

Bandit also ranked two findings in opposite directions from my assessment: it
rated the committed signing key LOW, and it flagged a harmless token-type
string as a possible password. A pipeline that files tool severities directly
as ticket severities would have mis-spent attention in both directions and
missed the cross-tenant exposure entirely.
