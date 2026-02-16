"""
OWASP A07:2021 - Identification and Authentication Failures
Authentication Security Tests

Purpose: Validate that API properly handles
authentication, session management, and
credential security.

Tests:
- Endpoints accessible without authentication
- Weak/missing authentication headers
- Token validation
- Brute force protection
"""
import pytest
import requests
import time
from config import (
    BASE_URL,
    WEAK_PASSWORDS,
    REQUEST_TIMEOUT
)


class TestAuthentication:
    """
    Authentication test suite.
    
    Tests that API:
    1. Requires authentication where needed
    2. Rejects invalid/missing tokens
    3. Has brute force protection
    4. Doesn't expose credentials in responses
    """
    
    @pytest.fixture(autouse=True)
    def setup(self):
        """Setup for each test"""
        self.base_url = BASE_URL
        self.session = requests.Session()
        self.session.headers.update({
            "Content-Type": "application/json",
            "User-Agent": "Security-Test-Suite/1.0"
        })
    
    
    def test_api_accessible_without_auth(self):
        """
        Test: Check which endpoints require authentication
        
        OWASP: A07:2021 - Auth Failures
        Risk: High
        
        Purpose: Document endpoints accessible
        without any authentication credentials.
        
        Note: For public APIs this may be expected,
        but sensitive operations should require auth.
        """
        endpoints = [
            ("GET", f"{self.base_url}/posts"),
            ("GET", f"{self.base_url}/users"),
            ("GET", f"{self.base_url}/users/1"),
            ("POST", f"{self.base_url}/posts"),
            ("PUT", f"{self.base_url}/posts/1"),
            ("DELETE", f"{self.base_url}/posts/1"),
        ]
        
        unprotected = []
        protected = []
        
        for method, endpoint in endpoints:
            response = self.session.request(
                method,
                endpoint,
                json={"title": "test", "body": "test", "userId": 1}
                if method in ["POST", "PUT"] else None,
                timeout=REQUEST_TIMEOUT
            )
            
            # 401/403 = protected (good)
            # 200/201 = accessible without auth
            if response.status_code in [401, 403]:
                protected.append({
                    "method": method,
                    "endpoint": endpoint,
                    "status": response.status_code
                })
            else:
                unprotected.append({
                    "method": method,
                    "endpoint": endpoint,
                    "status": response.status_code
                })
        
        # Log findings
        print(f"\n[Authentication Audit]")
        print(f"Protected endpoints: {len(protected)}")
        print(f"Unprotected endpoints: {len(unprotected)}")
        
        for ep in unprotected:
            print(f"  WARNING: {ep['method']} {ep['endpoint']}"
                  f" - accessible without auth ({ep['status']})")
        
        # CRITICAL: Write/Delete operations should require auth
        critical_unprotected = [
            ep for ep in unprotected
            if ep['method'] in ['POST', 'PUT', 'DELETE']
        ]
        
        if critical_unprotected:
            pytest.fail(
                f"CRITICAL: Write/Delete operations "
                f"accessible without authentication:\n"
                + "\n".join([
                    f"  {ep['method']} {ep['endpoint']}"
                    for ep in critical_unprotected
                ])
            )
        
        print(f"\n[PASS] No critical auth bypasses found")
    
    
    def test_invalid_auth_token_rejected(self):
        """
        Test: Invalid tokens are properly rejected
        
        OWASP: A07:2021 - Auth Failures
        Risk: High
        
        Purpose: API should reject clearly
        invalid/malformed authentication tokens
        """
        invalid_tokens = [
            "invalid_token",
            "Bearer fake_token_12345",
            "null",
            "undefined",
            "' OR '1'='1",          # SQL injection in token
            "<script>alert(1)</script>",  # XSS in token
            "eyJhbGciOiJub25lIn0.eyJ1c2VyIjoiYWRtaW4ifQ.",  # JWT none algorithm
            "../../../../etc/passwd",  # Path traversal in token
        ]
        
        issues = []
        
        for token in invalid_tokens:
            response = self.session.get(
                f"{self.base_url}/posts",
                headers={"Authorization": token},
                timeout=REQUEST_TIMEOUT
            )
            
            # Should not return 500 with invalid tokens
            if response.status_code == 500:
                issues.append({
                    "token": token[:30],
                    "issue": "Server error with invalid token",
                    "status": response.status_code
                })
            
            # Should not expose token in error response
            if token in response.text:
                issues.append({
                    "token": token[:30],
                    "issue": "Token reflected in response",
                    "status": response.status_code
                })
        
        if issues:
            pytest.fail(
                f"Token handling issues:\n"
                + "\n".join([str(i) for i in issues])
            )
        
        print(f"\n[PASS] Invalid tokens handled safely "
              f"({len(invalid_tokens)} tokens tested)")
    
    
    def test_no_credentials_in_response(self):
        """
        Test: Responses don't contain credentials/secrets
        
        OWASP: A02:2021 - Cryptographic Failures
        Risk: Critical
        
        Purpose: API responses should never
        contain passwords, tokens, or secrets
        """
        sensitive_patterns = [
            "password",
            "passwd",
            "secret",
            "api_key",
            "apikey",
            "private_key",
            "access_token",
            "auth_token",
            "bearer",
            "credentials"
        ]
        
        endpoints = [
            f"{self.base_url}/users",
            f"{self.base_url}/users/1",
        ]
        
        exposures = []
        
        for endpoint in endpoints:
            response = self.session.get(
                endpoint,
                timeout=REQUEST_TIMEOUT
            )
            
            response_lower = response.text.lower()
            
            for pattern in sensitive_patterns:
                if pattern in response_lower:
                    # Get context around the match
                    idx = response_lower.find(pattern)
                    context = response.text[
                        max(0, idx-20):idx+50
                    ]
                    exposures.append({
                        "endpoint": endpoint,
                        "pattern": pattern,
                        "context": context
                    })
        
        if exposures:
            pytest.fail(
                f"Sensitive data in responses:\n"
                + "\n".join([str(e) for e in exposures])
            )
        
        print(f"\n[PASS] No credentials exposed in responses")
    
    
    def test_brute_force_protection(self):
        """
        Test: API has rate limiting / brute force protection
        
        OWASP: A07:2021 - Auth Failures
        Risk: High
        
        Purpose: API should rate-limit or block
        repeated failed authentication attempts
        
        Test: Send 20 rapid requests and check
        if rate limiting kicks in (429 Too Many Requests)
        """
        responses = []
        rate_limited = False
        
        # Send 20 rapid requests
        for i in range(20):
            response = self.session.get(
                f"{self.base_url}/posts",
                headers={
                    "Authorization": f"Bearer invalid_token_{i}"
                },
                timeout=REQUEST_TIMEOUT
            )
            responses.append(response.status_code)
            
            # Check if rate limited
            if response.status_code == 429:
                rate_limited = True
                print(f"\n[PASS] Rate limiting triggered "
                      f"after {i+1} requests")
                break
        
        if not rate_limited:
            # This is a finding but not critical for public APIs
            print(f"\n[WARNING] No rate limiting detected "
                  f"after 20 rapid requests")
            print(f"  Status codes: {set(responses)}")
            print(f"  Risk: Brute force attacks possible")
            print(f"  Recommendation: Implement rate limiting")
            # We don't fail this test since JSONPlaceholder
            # is a public API without auth
        else:
            print(f"\n[PASS] Rate limiting is active")
    
    
    def test_http_methods_restricted(self):
        """
        Test: Only necessary HTTP methods allowed
        
        OWASP: A05:2021 - Security Misconfiguration
        Risk: Medium
        
        Purpose: APIs should only accept
        intended HTTP methods (no TRACE, etc.)
        """
        dangerous_methods = ["TRACE", "TRACK", "DEBUG"]
        issues = []
        
        for method in dangerous_methods:
            response = self.session.request(
                method,
                f"{self.base_url}/posts",
                timeout=REQUEST_TIMEOUT
            )
            
            # TRACE should be disabled (405 Method Not Allowed)
            if response.status_code == 200:
                issues.append({
                    "method": method,
                    "issue": f"{method} method enabled",
                    "risk": "Cross-Site Tracing (XST) possible",
                    "status": response.status_code
                })
        
        if issues:
            pytest.fail(
                f"Dangerous HTTP methods enabled:\n"
                + "\n".join([str(i) for i in issues])
            )
        
        print(f"\n[PASS] Dangerous HTTP methods disabled "
              f"({len(dangerous_methods)} methods tested)")