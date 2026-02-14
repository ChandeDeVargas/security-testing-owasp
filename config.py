"""
Security Testing Configuration
OWASP Top 10 - Test Settings
"""

# Target API (safe for testing - public API)
BASE_URL = "https://jsonplaceholder.typicode.com"

# Secondary targets for header testing
HTTPBIN_URL = "https://httpbin.org"

# SQL Injection Payloads
SQL_INJECTION_PAYLOADS = [
    "' OR '1'='1",
    "' OR '1'='1' --",
    "' OR '1'='1' /*",
    "' OR 1=1 --",
    "'; DROP TABLE users; --",
    "' UNION SELECT NULL --",
    "admin'--",
    "' OR 'x'='x",
    "1; SELECT * FROM users",
    "' AND 1=0 UNION SELECT NULL, NULL --"
]

# XSS Payloads
XSS_PAYLOADS = [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert('XSS')>",
    "<svg onload=alert('XSS')>",
    "javascript:alert('XSS')",
    "<iframe src='javascript:alert(1)'>",
    "'\"><script>alert('XSS')</script>",
    "<body onload=alert('XSS')>",
    "<<SCRIPT>alert('XSS');//<</SCRIPT>"
]

# Security Headers to validate
REQUIRED_SECURITY_HEADERS = [
    "X-Content-Type-Options",
    "X-Frame-Options",
    "X-XSS-Protection",
    "Strict-Transport-Security",
    "Content-Security-Policy"
]

# Expected header values
EXPECTED_HEADER_VALUES = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": ["DENY", "SAMEORIGIN"],
    "X-XSS-Protection": "1; mode=block"
}

# Auth test settings
WEAK_PASSWORDS = [
    "password",
    "123456",
    "admin",
    "test",
    "root",
    "qwerty"
]

# Test timeouts
REQUEST_TIMEOUT = 10

# Report settings
REPORT_TITLE = "OWASP Security Test Report"
REPORT_DIR = "reports"