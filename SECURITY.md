# ROOTPRINT — Security Architecture

## OWASP Top 10 Coverage

| ID  | Vulnerability              | Implementation                                                                                      |
|-----|----------------------------|-----------------------------------------------------------------------------------------------------|
| A01 | Broken Access Control      | CSRF token system (HMAC-signed, single-use). HTTP method enforcement per route. Origin validation.  |
| A02 | Cryptographic Failures     | HMAC-SHA256 session signing. API keys never logged (masked to first 4 chars). HTTPS recommended.    |
| A03 | Injection                  | All input sanitised via `sanitise_str()`. Regex allowlists for IDs, services, search. No `eval`.    |
| A04 | Insecure Design            | Rate limiting per IP per endpoint. Request body size cap (16KB). Response size cap (2MB).           |
| A05 | Security Misconfiguration  | All security headers set (CSP, X-Frame-Options, HSTS). No directory listing. Debug off by default.  |
| A06 | Vulnerable Components      | Zero external dependencies. Python stdlib only. No npm. Attack surface: one process.                |
| A07 | Auth & Session Failures    | HMAC-signed session tokens. Constant-time comparison (prevents timing attacks). 24h expiry.         |
| A08 | Software & Data Integrity  | Atomic file writes (tmp → replace). Path traversal prevention with `resolve()` + `is_relative_to`. |
| A09 | Logging & Monitoring       | Structured security event log (`data/security.log`). Rate limit events, SSRF blocks, CSRF failures. |
| A10 | SSRF                       | Strict domain allowlist for all outbound fetches. Private IP blocks. Scheme enforcement.            |

---

## Security Controls Detail

### Input Validation (A03, A04)

```python
# All string inputs sanitised
def sanitise_str(s, max_len=MAX_FIELD_LEN) -> str:
    s = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]', '', str(s))
    return s[:max_len]

# Allowlist patterns — reject anything not matching
SAFE_IDENTIFIER = re.compile(r'^(rss:https?://[...]+|@[a-zA-Z0-9_]{1,64})$')
SAFE_SERVICE    = re.compile(r'^[a-z_]{1,32}$')
SAFE_UUID       = re.compile(r'^[a-f0-9]{1,32}$')
```

### Output Encoding — XSS Prevention (A03)

Frontend uses DOM API exclusively — no `innerHTML` with user data:
```javascript
// SAFE — DOM text node (auto-escapes everything)
function esc(s) {
    const d = document.createElement('div');
    d.appendChild(document.createTextNode(String(s ?? '')));
    return d.innerHTML;
}
// Feed card titles use esc() before insertion
// IOC values use esc() — never raw string interpolation with user data
```

### SSRF Protection (A10)

```python
FETCH_ALLOWLIST = {'bleepingcomputer.com', 'virustotal.com', ...}

def is_allowed_url(url_str: str) -> bool:
    parsed = urlparse(url_str)
    if parsed.scheme not in ('http', 'https'): return False
    # Block all private/loopback IPs
    try:
        addr = ipaddress.ip_address(parsed.hostname)
        if addr.is_private or addr.is_loopback: return False
    except ValueError: pass
    return any(host == d or host.endswith('.'+d) for d in FETCH_ALLOWLIST)
```

### Rate Limiting (A04)

| Endpoint          | Limit          |
|-------------------|----------------|
| GET (all)         | 60 req / 60s   |
| POST /api/ingest  | 3 req / 60s    |
| POST /api/config  | 20 req / 60s   |
| POST /api/sources | 10 req / 60s   |
| DELETE            | 30 req / 60s   |

### HTTP Security Headers (A05)

```
Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'; ...
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
X-XSS-Protection: 1; mode=block
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: geolocation=(), microphone=(), camera=()
Cache-Control: no-store (API responses)
```

### Path Traversal Prevention (A08)

```python
def safe_static_path(requested: str) -> Path | None:
    resolved = (STATIC / requested).resolve()
    # Ensures path stays inside STATIC directory
    if not resolved.is_relative_to(STATIC.resolve()):
        sec_log.warning(f'PATH_TRAVERSAL attempted={requested}')
        return None
    return resolved
```

### Atomic File Writes (A08)

```python
def write_json(path: Path, data):
    tmp = path.with_suffix('.tmp')
    tmp.write_text(json.dumps(data, ...), encoding='utf-8')
    tmp.replace(path)  # Atomic on POSIX systems
    path.chmod(0o600)  # Owner read/write only
```

### Session Security (A07)

```python
def create_session(data: dict) -> str:
    token = token_urlsafe(32)           # 256-bit entropy
    sig   = hmac.new(SECRET_KEY.encode(), token.encode(), hashlib.sha256).hexdigest()
    ...

def validate_session(token: str) -> dict | None:
    # Constant-time HMAC comparison — prevents timing attacks
    if not hmac.compare_digest(sess.get('sig', ''), expected_sig):
        sec_log.warning(f'SESSION_TAMPER ...')
        return None
```

---

## Security Testing Recommendations

### Static Analysis (SAST)

```bash
# Python — Bandit (find common security bugs)
pip install bandit
bandit -r server.py -ll

# Python — Safety (check for known vulnerable packages)
pip install safety
safety check

# Python — Semgrep (rule-based static analysis)
pip install semgrep
semgrep --config=p/python-security server.py
```

### Dynamic Analysis (DAST)

```bash
# OWASP ZAP baseline scan (requires server running)
docker run -t owasp/zap2docker-stable zap-baseline.py \
  -t http://localhost:7117

# Nikto web server scanner
nikto -h http://localhost:7117

# SQLMap (not applicable here — no SQL, but useful if DB added)
```

### Dependency Audit

```bash
# Since we use no external deps, audit Python itself
python --version  # Ensure 3.12+ (latest security patches)
```

### Manual Security Checklist

- [ ] `SECRET_KEY` set to random 32+ byte hex (not default)
- [ ] `DEBUG=false` in production
- [ ] Server bound to `127.0.0.1` only (not `0.0.0.0`) unless behind reverse proxy
- [ ] HTTPS configured (nginx/caddy as TLS terminator)
- [ ] `data/` directory not web-accessible
- [ ] `data/config.json` permissions: `600` (owner only)
- [ ] Security log reviewed regularly: `tail -f data/security.log`
- [ ] Rate limiting thresholds tuned for expected traffic
- [ ] FETCH_ALLOWLIST reviewed when adding new enrichment sources

### Production Hardening

```bash
# Generate a strong SECRET_KEY
python -c "import secrets; print(secrets.token_hex(32))"

# Set file permissions
chmod 700 data/
chmod 600 data/*.json

# Run behind nginx with TLS
# nginx.conf: proxy_pass http://127.0.0.1:7117;
```

---

## Threat Model

| Threat                  | Likelihood | Impact | Mitigation                              |
|-------------------------|------------|--------|-----------------------------------------|
| XSS via feed titles     | Medium     | High   | DOM-based output encoding (esc())       |
| SSRF via source URLs    | Medium     | High   | Domain allowlist + private IP block     |
| Path traversal          | Low        | High   | resolve() + is_relative_to() check      |
| Credential exposure     | Medium     | High   | sessionStorage (not localStorage); no server-side logging |
| Rate abuse / DoS        | Medium     | Medium | Per-IP rate limiting on all endpoints   |
| Config file exfiltration| Low        | High   | Keys never returned from API; chmod 600 |
| Session hijacking       | Low        | Medium | HMAC-signed tokens; short expiry        |

---

## Compliance Notes

- **GDPR**: No PII collected. No analytics. No telemetry.
- **Data retention**: Feeds capped at 5000 records; IOCs capped at 10000 records.
- **API keys**: Stored locally on disk, never transmitted to third parties by ROOTPRINT itself.
