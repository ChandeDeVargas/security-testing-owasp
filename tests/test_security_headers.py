"""
OWASP A05:2021 - Security Misconfiguration
Security Headers Tests

Purpose: Validate that API responses include
proper security headers to protect against
common web vulnerabilities.

Headers tested:
- X-Content-Type-Options
- X-Frame-Options
- X-XSS-Protection
- Strict-Transport-Security
- Content-Security-Policy
- Cache-Control
"""
import pytest
import requests
from config import (
    BASE_URL,
    HTTPBIN_URL,
    REQUIRED_SECURITY_HEADERS,
    EXPECTED_HEADER_VALUES,
    REQUEST_TIMEOUT
)

class TestSecurityHeaders:
    """Security Headers test suite

    Tests that API responses include:
    1. Required security headers
    2. Correct header values
    3. No dangerous headers exposed
    4. Proper cache control
    """

    @pytest.fixture(autouse=True)
    def setup(self):
        """Setup for each test"""
        self.base_url = BASE_URL
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Security-Test-Suite/1.0"
        })

        # Get response for reuse
        self.response = self.session.get(
            f"{self.base_url}/posts/1",
            timeout=REQUEST_TIMEOUT
        )

    def test_x_content_type_options_header(self):
        """
        Test: X-Content-Type-Options header present

        OWASP: A05:2021 - Security Misconfiguraiton
        Risk: Medium

        Purpose: Prevents MIME-type sniffing attacks
        Expected value: "nosniff"
        
        Without this header: Browser might execute
        a text file as JavaScript (MIME confusion attack)
        """
        header_name = "X-Content-Type-Options"
        header_value = self.response.headers.get(header_name)
        
        if not header_value:
            pytest.fail(
                f"MISSING HEADER: {header_name}\n"
                f"Risk: Browser may perfom MIME sniffing\n"
                f"Fix: Add '{header_name}: nosniff' to response"
            )

        if header_value.lower() != "nosniff":
            pytest.fail(
                f"INVALID VALUE: {header_name}: {header_value}\n"
                f"Expected: nosniff\n"
                f"Risk: MIME sniffing protection disabled"
            )
        
        print(f"\n✅ {header_name}: {header_value}")

    def test_x_frame_options_header(self):
        """
        Test: X-Frame-Options header present

        OWASP: A05:2021 - Security Misconfiguration
        Risk: High

        Purpose: Prevents clickjacking attacks
        Expected value: "DENY" or "SAMEORIGIN"
        
        Without this header: Attackers can embed
        your page in an iframe to trick users
        """
        header_name = "X-Frame-Options"
        header_value = self.response.headers.get(header_name)

        if not header_value:
            pytest.fail(
                f"MISSING HEADER: {header_name}\n"
                f"Risk: Clickjacking attacks possible\n"
                f"Fix: Add '{header_name}: DENY' to responses"
            )
        
        valid_values = ["DENY", "SAMEORIGIN"]
        if header_value.upper() not in valid_values:
            pytest.fail(
                f"INVALID VALUE: {header_name}: {header_value}\n"
                f"Expected: DENY or SAMEORIGIN\n"
                f"Risk: Clickjacking protection ineffective"
            )
        
        print(f"\n✅ {header_name}: {header_value}")


    def test_strict_transport_security_header(self):
        """
        Test: Strict-Transport-Security (HSTS) header
        
        OWASP: A02:2021 - Cryptographic Failures
        Risk: High
        
        Purpose: Forces HTTPS connections
        Expected: max-age=31536000 (1 year minimum)
        
        Without this header: Users can be
        downgraded to HTTP (man-in-the-middle attacks)
        """
        header_name = "Strict-Transport-Security"
        header_value = self.response.headers.get(header_name)
        
        if not header_value:
            pytest.fail(
                f"MISSING HEADER: {header_name}\n"
                f"Risk: HTTP downgrade attacks possible\n"
                f"Fix: Add '{header_name}: max-age=31536000' to responses"
            )
        
        # Check max-age is present and sufficient
        if "max-age" not in header_value.lower():
            pytest.fail(
                f"INVALID VALUE: {header_name}: {header_value}\n"
                f"Missing: max-age directive\n"
                f"Risk: HSTS not properly configured"
            )
        
        print(f"\n {header_name}: {header_value}")
    
    
    def test_content_security_policy_header(self):
        """
        Test: Content-Security-Policy (CSP) header
        
        OWASP: A03:2021 - XSS Prevention
        Risk: High
        
        Purpose: Prevents XSS and injection attacks
        by controlling resource loading
        
        Without this header: No browser-level
        protection against XSS attacks
        """
        header_name = "Content-Security-Policy"
        header_value = self.response.headers.get(header_name)
        
        if not header_value:
            pytest.fail(
                f"MISSING HEADER: {header_name}\n"
                f"Risk: No XSS browser-level protection\n"
                f"Fix: Add Content-Security-Policy header\n"
                f"Example: default-src 'self'"
            )
        
        print(f"\n {header_name}: {header_value}")
    
    
    def test_no_server_version_exposed(self):
        """
        Test: Server header doesn't expose version info
        
        OWASP: A05:2021 - Security Misconfiguration
        Risk: Medium
        
        Purpose: Version info helps attackers
        find known vulnerabilities
        
        Bad: Server: Apache/2.4.1 (reveals version)
        Good: Server: Apache (no version)
        Better: No Server header at all
        """
        server_header = self.response.headers.get("Server", "")
        x_powered_by = self.response.headers.get("X-Powered-By", "")
        
        issues = []
        
        # Check for version numbers in Server header
        import re
        version_pattern = r'\d+\.\d+'
        
        if re.search(version_pattern, server_header):
            issues.append(
                f"Server header exposes version: {server_header}"
            )
        
        if x_powered_by:
            issues.append(
                f"X-Powered-By header exposed: {x_powered_by}\n"
                f"Fix: Remove X-Powered-By header completely"
            )
        
        if issues:
            pytest.fail(
                f"Server information exposed:\n"
                + "\n".join(issues)
            )
        
        print(f"\n Server info: No version numbers exposed")
        if server_header:
            print(f"   Server header: {server_header}")
        if not x_powered_by:
            print(f"   X-Powered-By: Not present (good!)")
    
    
    def test_cache_control_for_sensitive_endpoints(self):
        """
        Test: Cache-Control header on sensitive endpoints
        
        OWASP: A02:2021 - Cryptographic Failures
        Risk: Medium
        
        Purpose: Prevents sensitive data from
        being cached by browsers or proxies
        
        Expected: no-store or no-cache
        """
        sensitive_endpoints = [
            f"{self.base_url}/users",
            f"{self.base_url}/users/1",
        ]
        
        issues = []
        
        for endpoint in sensitive_endpoints:
            response = self.session.get(
                endpoint,
                timeout=REQUEST_TIMEOUT
            )
            
            cache_control = response.headers.get(
                "Cache-Control", ""
            ).lower()
            
            # Sensitive data shouldn't be cached
            if not cache_control:
                issues.append(
                    f"Missing Cache-Control on: {endpoint}\n"
                    f"Risk: Sensitive data may be cached"
                )
            elif "no-store" not in cache_control and \
                 "no-cache" not in cache_control and \
                 "private" not in cache_control:
                issues.append(
                    f"Weak Cache-Control on: {endpoint}\n"
                    f"Current: {cache_control}\n"
                    f"Expected: no-store, no-cache, or private"
                )
        
        if issues:
            pytest.fail(
                f"Cache-Control issues on sensitive endpoints:\n"
                + "\n".join(issues)
            )
        
        print(f"\n Cache-Control: "
              f"All {len(sensitive_endpoints)} sensitive "
              f"endpoints checked")
    
    
    def test_cors_headers_not_wildcard(self):
        """
        Test: CORS headers are not overly permissive
        
        OWASP: A05:2021 - Security Misconfiguration
        Risk: High
        
        Purpose: Wildcard CORS (*) allows any
        website to make requests to your API
        
        Bad:  Access-Control-Allow-Origin: *
        Good: Access-Control-Allow-Origin: https://yoursite.com
        """
        response = self.session.options(
            f"{self.base_url}/posts",
            timeout=REQUEST_TIMEOUT
        )
        
        cors_header = response.headers.get(
            "Access-Control-Allow-Origin", ""
        )
        
        issues = []
        
        if cors_header == "*":
            issues.append(
                f"CRITICAL: Wildcard CORS detected\n"
                f"Access-Control-Allow-Origin: *\n"
                f"Risk: Any website can access this API\n"
                f"Fix: Specify allowed origins explicitly"
            )
        
        if issues:
            pytest.fail("\n".join(issues))
        
        if cors_header:
            print(f"\nCORS: {cors_header}")
        else:
            print(f"\nCORS: No wildcard detected")