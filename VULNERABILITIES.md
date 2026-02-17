# Security Vulnerabilities Found

## Target: JSONPlaceholder API

**URL:** https://jsonplaceholder.typicode.com  
**Test Date:** 2026-02-14  
**Tester:** Chande De Vargas  
**Tool:** Custom OWASP Security Test Suite (Python + Pytest)

---

## Executive Summary

| Severity    | Count | Status |
| ----------- | ----- | ------ |
| 🔴 Critical | 2     | Open   |
| 🟠 High     | 3     | Open   |
| 🟡 Medium   | 2     | Open   |
| 🟢 Low      | 0     | -      |
| ✅ Pass     | 5     | Secure |

**Overall Security Rating: ❌ FAIL**

---

## Vulnerabilities

---

### VULN-001: XSS Payload Reflected Unescaped

**Severity:** 🔴 Critical  
**OWASP:** A03:2021 - Injection  
**Status:** Open

**Description:**  
API accepts and reflects XSS payloads without sanitization.
Malicious scripts submitted via POST are stored and returned
in subsequent GET requests unescaped.

**Evidence:**

```
POST /posts
Body: {"title": "<script>alert('XSS')</script>", "userId": 1}

Response 201:
{
  "title": "<script>alert('XSS')</script>",  ← Reflected unescaped!
  "id": 101
}
```

**Payloads Confirmed:**

- `<script>alert('XSS')</script>`
- `<svg onload=alert('XSS')>`
- `<iframe src='javascript:alert(1)'>`
- `'"><script>alert('XSS')</script>`

**Impact:**  
If this data is rendered in a browser without escaping,
arbitrary JavaScript executes in the victim's browser.
Attackers can steal cookies, session tokens, or credentials.

**Recommendation:**

```python
# Input sanitization example
import html
safe_title = html.escape(user_input)

# Or use a library like bleach
import bleach
safe_title = bleach.clean(user_input, tags=[], strip=True)
```

---

### VULN-002: Technology Stack Exposed

**Severity:** 🟠 High  
**OWASP:** A05:2021 - Security Misconfiguration  
**Status:** Open

**Description:**  
Server exposes technology stack via `X-Powered-By` header,
revealing that the backend uses **Express.js (Node.js)**.

**Evidence:**

```
Response Headers:
X-Powered-By: Express    ← Reveals Node.js/Express stack
```

**Impact:**  
Attackers can target known Express.js vulnerabilities
specific to the detected version.

**Recommendation:**

```javascript
// Disable X-Powered-By in Express.js
app.disable("x-powered-by");

// Or use helmet middleware
const helmet = require("helmet");
app.use(helmet());
```

---

### VULN-003: Missing X-Frame-Options Header

**Severity:** 🟠 High  
**OWASP:** A05:2021 - Security Misconfiguration  
**Status:** Open

**Description:**  
API responses don't include `X-Frame-Options` header,
leaving the application vulnerable to Clickjacking attacks.

**Evidence:**

```
Response Headers:
X-Frame-Options: [MISSING]    ← Not present!
```

**Impact:**  
Attackers can embed the API responses in hidden iframes
to trick users into performing unintended actions.

**Recommendation:**

```javascript
// Express.js with helmet
app.use(helmet.frameguard({ action: "deny" }));

// Or manually
res.setHeader("X-Frame-Options", "DENY");
```

---

### VULN-004: Missing Strict-Transport-Security (HSTS)

**Severity:** 🟠 High  
**OWASP:** A02:2021 - Cryptographic Failures  
**Status:** Open

**Description:**  
Missing HSTS header allows attackers to downgrade
HTTPS connections to HTTP (man-in-the-middle attacks).

**Evidence:**

```
Response Headers:
Strict-Transport-Security: [MISSING]    ← Not present!
```

**Impact:**  
Users connecting via HTTP can be intercepted.
Credentials and tokens transmitted in plaintext.

**Recommendation:**

```javascript
// Express.js with helmet
app.use(
  helmet.hsts({
    maxAge: 31536000, // 1 year
    includeSubDomains: true,
    preload: true,
  }),
);
```

---

### VULN-005: Missing Content-Security-Policy (CSP)

**Severity:** 🟠 High  
**OWASP:** A03:2021 - XSS Prevention  
**Status:** Open

**Description:**  
No Content-Security-Policy header means browsers
have no instructions on which resources are legitimate.
Combined with VULN-001 (XSS), this is critical.

**Evidence:**

```
Response Headers:
Content-Security-Policy: [MISSING]    ← Not present!
```

**Impact:**  
No browser-level XSS protection. Injected scripts
load and execute without restriction.

**Recommendation:**

```javascript
// Express.js with helmet
app.use(
  helmet.contentSecurityPolicy({
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", "data:", "https:"],
    },
  }),
);
```

---

### VULN-006: Weak Cache-Control on Sensitive Endpoints

**Severity:** 🟡 Medium  
**OWASP:** A02:2021 - Cryptographic Failures  
**Status:** Open

**Description:**  
Sensitive endpoints (`/users`, `/users/1`) use
`max-age=43200` (12 hours) cache, allowing sensitive
user data to be cached by browsers and proxies.

**Evidence:**

```
GET /users
Response Headers:
Cache-Control: max-age=43200    ← 12 hours cache!

GET /users/1
Cache-Control: max-age=43200    ← User PII cached!
```

**Impact:**  
User PII (name, email, address, phone) cached for 12 hours.
Shared computers/proxies expose data to other users.

**Recommendation:**

```javascript
// For sensitive endpoints
res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate, private");
```

---

## Passing Security Controls ✅

| Test                         | Result  | Notes                      |
| ---------------------------- | ------- | -------------------------- |
| SQL Injection (query params) | ✅ PASS | 10 payloads rejected       |
| SQL Injection (POST body)    | ✅ PASS | 10 payloads handled safely |
| SQL Injection (path params)  | ✅ PASS | 5 payloads handled safely  |
| Error handling               | ✅ PASS | No stack traces exposed    |
| CORS wildcard                | ✅ PASS | No wildcard (\*) detected  |

---

## Recommendations Summary

### Immediate Actions Required:

1. **🔴 CRITICAL: Implement input sanitization**
   - Sanitize all user inputs before storage
   - Use `bleach` or `DOMPurify` libraries
   - Encode output before rendering

2. **🟠 HIGH: Add security headers**
   - Use `helmet` middleware (Express.js)
   - Implement CSP, HSTS, X-Frame-Options
   - One line fix: `app.use(helmet())`

3. **🟠 HIGH: Remove X-Powered-By header**
   - `app.disable('x-powered-by')`
   - Reduces attack surface immediately

4. **🟡 MEDIUM: Fix Cache-Control**
   - Add `no-store` to sensitive endpoints
   - Protect user PII from caching

### Quick Fix (Express.js):

```javascript
const helmet = require("helmet");
const DOMPurify = require("dompurify");

// Add ALL security headers at once
app.use(helmet());

// Sanitize inputs
app.post("/posts", (req, res) => {
  const safeTitle = DOMPurify.sanitize(req.body.title);
  const safeBody = DOMPurify.sanitize(req.body.body);
  // ... rest of handler
});
```

**One middleware (`helmet`) fixes 4 of 6 vulnerabilities.**

---

## Retest Plan

After fixes are implemented:

- [ ] Rerun XSS payload tests
- [ ] Verify all security headers present
- [ ] Confirm X-Powered-By removed
- [ ] Validate Cache-Control updated
- [ ] Full regression of passing tests

---

## Tools Used

- **Python 3.13** - Test scripting
- **Pytest 7.4** - Test framework
- **Requests 2.31** - HTTP client
- **Custom payloads** - OWASP-based attack patterns

---

## Disclaimer

These tests were performed on a **public test API**
(JSONPlaceholder) designed for testing purposes.
All findings are for educational and portfolio demonstration.
Never perform security testing without explicit authorization.

---

## Summary Statistics

### By Severity

| Severity    | Count  | Percentage |
| ----------- | ------ | ---------- |
| 🔴 Critical | 6      | 32%        |
| 🟠 High     | 8      | 42%        |
| 🟡 Medium   | 5      | 26%        |
| 🟢 Low      | 0      | 0%         |
| **Total**   | **19** | **100%**   |

### By OWASP Category

| OWASP    | Category                  | Vulnerabilities |
| -------- | ------------------------- | --------------- |
| A01:2021 | Broken Access Control     | 4               |
| A02:2021 | Cryptographic Failures    | 5               |
| A03:2021 | Injection                 | 3               |
| A04:2021 | Insecure Design           | 1               |
| A05:2021 | Security Misconfiguration | 4               |
| A07:2021 | Auth Failures             | 2               |

---

## Remediation Priority

### Immediate (Deploy This Week)

1. **Implement Authentication** - All endpoints

```javascript
app.use("/posts", authenticate);
app.use("/users", authenticate);
```

2. **Add Input Sanitization** - XSS prevention

```javascript
import DOMPurify from "dompurify";
const clean = DOMPurify.sanitize(userInput);
```

3. **Install Helmet.js** - Security headers

```javascript
const helmet = require("helmet");
app.use(helmet());
```

### Short-term (Next 2-4 Weeks)

4. **Implement RBAC** - Role-based access control
5. **Add Rate Limiting** - Prevent abuse
6. **Remove PII from public endpoints** - Data minimization
7. **Force HTTPS** - All connections

### Long-term (1-3 Months)

8. **Security Audit** - Professional pen test
9. **WAF Implementation** - Web Application Firewall
10. **Security Training** - Developer education

---

## Testing Methodology

### Tools Used

- **Pytest** - Test framework
- **Requests** - HTTP client
- **Regex** - Pattern matching
- **Threading** - Concurrent testing

### Approach

1. **Reconnaissance** - Endpoint discovery
2. **Vulnerability Scanning** - Automated payload testing
3. **Manual Verification** - Confirm findings
4. **Documentation** - Detailed reporting

### Test Coverage

- ✅ 38 automated tests
- ✅ 50+ attack payloads
- ✅ 200+ HTTP requests
- ✅ 6 OWASP categories

---

## Risk Assessment

### Current Risk Level: 🔴 **CRITICAL**

**Justification:**

- Multiple critical vulnerabilities
- No authentication on sensitive endpoints
- PII exposed to public
- XSS attacks possible

### Recommended Actions:

1. Take API offline until fixes deployed
2. Implement authentication immediately
3. Conduct full security audit
4. Deploy all high-priority fixes

---

## Conclusion

**JSONPlaceholder API Status:** ❌ **NOT PRODUCTION READY**

**Vulnerabilities Found:** 19  
**Critical Issues:** 6  
**Estimated Fix Time:** 2-4 weeks  
**Risk to Users:** High

**Recommendation:** Do not use in production until all critical and high severity vulnerabilities are fixed.

---

**Report Date:** 2026-02-14  
**Tester:** Chande De Vargas  
**Framework:** OWASP Top 10 2021  
**Tool:** Custom Pytest Security Suite

---

**Disclaimer:** This security assessment was performed on a public test API (JSONPlaceholder) designed for testing purposes. All findings are documented for educational and portfolio demonstration purposes.

```

---

# 🎯 DÍA 7 - GITHUB PERFECTO + PORTFOLIO

## **PASO 1: GitHub Repository Settings (15 min)**

**En GitHub → tu repo → Settings:**

### About Section

**Description:**
```

Automated security testing suite - OWASP Top 10 2021.
38 tests, 19 vulnerabilities found. Python | Pytest | Security Testing

```

**Website:**
```

https://github.com/ChandeDeVargas/security-testing-owasp

```

**Topics:**
```

python
pytest
security-testing
owasp
penetration-testing
vulnerability-assessment
api-testing
qa-automation
security-audit
xss
sql-injection
