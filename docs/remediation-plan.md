# Security Remediation Plan & Residual Risks

## Remediated in Code
The following high and critical findings were remediated directly in code:

1. **SQL Injection in Query Search (`app/database.py`):**
   - *Fix:* Replaced raw string interpolation with SQLAlchemy parameter binding (`:pattern`).
   - *Result:* SQLite safely escapes user inputs, neutralizing injection vectors.

2. **JWT Algorithm Confusion (`app/auth.py`):**
   - *Fix:* Removed `"none"` from accepted decode algorithms, strictly enforcing `algorithms=[ALGORITHM]`.
   - *Result:* Unsigned or tampered identity tokens are rejected.

3. **Insecure Direct Object Reference (`app/main.py`):**
   - *Fix:* Enforced explicit ownership checks (`models.ScanResult.owner_id == current_user.id`) across both `get_scan` and `create_share_link`.
   - *Result:* Users can only inspect and share scans they own.

4. **Credential Logging Sanitization (`app/main.py`):**
   - *Fix:* Stripped plaintext passwords from `logger.info` and `logger.warning` calls during authentication.
   - *Result:* Application logs retain audit trails without leaking cleartext credentials.

---

## Residual Risks & Deferred Remediations

### 1. In-Memory Token Store for Shared Links
- **Residual Risk:** Shared links reside in volatile memory (`SHARED_LINKS`). Application restarts or horizontal scaling across multiple pods will invalidate active links or cause cache misses.
- **Remediation Effort:** Requires provisioning an external Redis cluster or dedicated database table with TTL indexes.
- **Compensating Controls:** Tokens are generated with 256 bits of cryptographically secure entropy (`secrets.token_urlsafe(32)`), and expiration is checked on every read.

### 2. Distributed Rate Limiting on Shared Links
- **Residual Risk:** Attackers can attempt automated password guessing against password-protected shared links without being throttled by the application.
- **Remediation Effort:** Implementing a distributed Redis-backed rate limiter (e.g., `slowapi`) across ingress boundaries.
- **Compensating Controls:** Password hashing using `bcrypt` adds computational cost to brute-force attempts. Ingress/WAF layers can enforce rate limits at the edge.

### 3. Hardcoded Secrets in Local Configuration
- **Residual Risk:** Repository access exposes default keys if the application is run outside production orchestration.
- **Remediation Effort:** Refactoring `app/config.py` to use `pydantic-settings` to mandate environment variables or Kubernetes Secrets.
- **Compensating Controls:** Production Helm templates bind credentials via external secret stores, preventing local fallback values from deploying to production.
