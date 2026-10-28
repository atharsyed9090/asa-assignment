# Security Remediation Plan and Residual Risks

Companion to `docs/findings.md`. Part one covers what I fixed and how to check
it. Part two covers what I did not fix, with the risk that remains, the effort
to close it, and what compensates meanwhile.

## Remediated in code

**1. SQL injection in scan search (SEC-01, `app/database.py`)**
Replaced string interpolation with bound parameters. The `UNION SELECT` payload
that previously returned bcrypt hashes now returns zero rows.

**2. Search ignored record ownership (SEC-10, `app/database.py`)**
Added the `owner_id` predicate the statement never had. Worth separating from
the fix above: parameter binding alone still left the endpoint returning every
tenant's findings. Verified with two accounts — the second user's search for the
first user's finding now returns nothing.

**3. Missing ownership check on scan read (SEC-03, `app/main.py`)**
`GET /scans/{scan_id}` now filters on owner as well as id. It returns 404 rather
than 403 on purpose, so the response does not confirm that a scan with that id
exists.

**4. Credentials removed from source (SEC-06, `app/config.py`)**
All configuration now reads from the environment. With `APP_ENV=production` a
missing `SECRET_KEY` raises at startup rather than falling back to a committed
default; outside production there is a clearly-named development value. Nothing
secret is left in the repository or in the container image.

**5. Passwords removed from logs (SEC-04, `app/main.py`)**
The username is still logged on failure for monitoring. The submitted password
is not logged at all, on success or failure.

**6. Unsigned algorithm removed from JWT decode (SEC-02, `app/auth.py`)**
`"none"` is gone and only the configured algorithm is accepted. Testing showed
this was never an authentication bypass, but the line was indefensible either
way.

**7. Reflective CORS replaced (SEC-11, `app/main.py`)**
Explicit allowlist, empty by default, so no cross-origin access is granted
unless an operator configures it. `allow_credentials` is off, because this API
authenticates with a bearer header and credentialed CORS buys nothing here.

**8. Error responses no longer leak internals (SEC-12, `app/main.py`)**
The handler returns a generic message and logs the detail server-side. This also
removes the echo of failing SQL that made SEC-01 easier to exploit.

**9. Throttling on shared report links (SEC-05, `app/main.py`)**
Public share reads are limited per client address, which raises the cost of
guessing a share password. This is my own Task 1 code, and the limitation is
noted below.

**10. Container and Kubernetes hardening (SEC-08, `helm/`)**
Read-only root filesystem enabled, all capabilities dropped, `runAsNonRoot` with
a fixed UID, `seccompProfile: RuntimeDefault`, CPU and memory limits, liveness
and readiness probes, and a default-deny NetworkPolicy that admits traffic only
from the ingress controller on the API port. `SECRET_KEY` is delivered by the
External Secrets Operator, so the chart references names and remote keys only
and no secret value appears in any manifest.

---

## Residual risks and deferred work

Ordered by the risk that remains.

### 1. The committed credentials are still in git history

**Risk: High.** I removed all five from the working tree, but they remain in the
starter commits. Anyone who has ever cloned this repository still holds a working
JWT signing key, database password, admin API key and notify service key.
Deleting the lines did not undo their disclosure.

**Effort:** roughly an hour per credential including redeploy. Rewriting history
is a further couple of hours and requires coordinating with everyone holding a
clone.

**Compensating controls:** none in the application. There is no control that
compensates for a disclosed signing key — the only remediation is rotation.

**Recommendation:** treat all five as compromised and rotate before any
deployment. This is the item I would not ship without.

### 2. The notification service is still unauthenticated

**Risk: High** if the service is reachable beyond the pod network. An attacker
who reaches port 3001 can still register an arbitrary URL and have the service
fetch it carrying the internal service key.

**Effort:** four to six hours for URL validation plus a destination allowlist and
a shared-secret check. Closer to two days to do it properly with mutual TLS and a
real egress policy.

**Why deferred:** the brief scopes `notify/` out of code changes, and a correct
fix is a design decision about how internal services prove identity to each
other rather than a patch. Guessing at the intended trust boundary would be worse
than naming the gap.

**Compensating controls:** the NetworkPolicy is default-deny in both directions,
so only the API pod can reach the notify service and its own egress is limited to
DNS and that one port.

**Recommendation:** validate and allowlist webhook destination URLs first. That
removes the SSRF primitive for a fraction of the cost of mutual TLS.

### 3. Vulnerable dependency versions

**Risk: High on paper, lower in practice.** 67 Python advisories and 11 Node
advisories remain. The ones that genuinely matter are `python-jose`
CVE-2024-33663, because every request verifies a token through it, and `axios`
0.21.1's SSRF behaviour, because residual risk 2 lets an attacker pick the URL it
fetches.

**Effort:** two to three hours to upgrade and re-test. The Node upgrade crosses an
Express major version, so it needs more than a version bump.

**Compensating controls:** none specific. The exposure is bounded by the fact that
most of the advisory count sits in code paths this service never executes.

**Recommendation:** upgrade `python-jose` and `axios` first — those two are
reachable. The rest can follow on a normal patch cycle.

### 4. Share links live in process memory

**Risk: Medium.** Tokens are held in a module-level dictionary, so a restart
invalidates every live link, and with more than one replica a link created on one
pod is not found on another. The chart is set to a single replica for that reason,
which caps throughput.

**Effort:** three to four hours to move them to a database table with an expiry
column, which is the right answer here given a database already exists.

**Compensating controls:** tokens carry 256 bits of entropy from
`secrets.token_urlsafe(32)`, and expiry is checked server-side on every read, so
the weakness is availability and scale rather than confidentiality.

### 5. Rate limiting is per-process only

**Risk: Medium.** The share-link limiter counts in local memory, so counters reset
on restart and are not shared between replicas. Login and registration are not
throttled at all.

**Effort:** about three hours with a shared store such as Redis, or thirty minutes
if the ingress controller's own rate limiting is acceptable.

**Compensating controls:** bcrypt's work factor makes online password guessing
slow, and share tokens are long enough that guessing the token itself is not
feasible.

**Recommendation:** an ingress-level rate limit on `/auth/*` is the cheapest
meaningful improvement.

### 6. Inherited CVEs in the container base image

**Risk: Low to Medium.** 18 critical and 148 high findings come from the
`python:3.11.8-slim-bookworm` base, not from our code. They sit in OS utilities
the application never invokes, so they are reachable only after an attacker
already has execution in the container.

**Effort:** one to two hours to move to a current base image and re-verify, which
should clear most of them. Moving to a distroless image would clear more, at the
cost of losing a shell for debugging.

**Compensating controls:** non-root user, read-only root filesystem, all
capabilities dropped, no privilege escalation, and no package manager available at
runtime.

### 7. Remaining hardening

| Item | Risk | Effort |
| :--- | :--- | :--- |
| No password policy or breached-password check | Medium | 2h |
| SQLite in production — single writer, unencrypted at rest | Medium | 1 day |
| Image referenced by tag rather than digest (Checkov CKV_K8S_43) | Low | 15m |
| Service account token still mounted (CKV_K8S_38) | Low | 15m |
| No token revocation or `jti` claim — logout cannot invalidate a live token | Low | 4h |
| Unbounded `limit` on `/scans` | Low | 15m |
| User enumeration via login timing | Low | 30m |
