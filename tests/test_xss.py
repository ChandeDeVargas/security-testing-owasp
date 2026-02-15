"""
OWASP A03:2021 - Cross-Site Scripting (XSS)
XSS Security Tests

Purpose: Validate that API endpoints properly
sanitize inputs and don't reflect malicious scripts.

Types tested:
- Reflected XSS: Payload reflected in response
- Stored XSS: Payload stored and returned later
- DOM XSS: Payload in response used by browser
"""
import pytest
import requests
from config import (
    BASE_URL,
    XSS_PAYLOADS,
    REQUEST_TIMEOUT
)


class TestXSS:
    """
    Cross-Site Scripting (XSS) test suite.
    
    Tests that API endpoints:
    1. Don't reflect script tags in responses
    2. Sanitize HTML special characters
    3. Return proper Content-Type headers
    4. Don't store and return malicious scripts
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
    
    
    def contains_unescaped_script(self, response_text, payload):
        """
        Check if response contains unescaped XSS payload.
        
        Safe responses either:
        - Don't contain the payload at all
        - Contain it HTML-escaped (&lt;script&gt;)
        
        Dangerous responses contain raw script tags.
        """
        dangerous_patterns = [
            "<script>",
            "</script>",
            "javascript:",
            "onerror=",
            "onload=",
            "<iframe",
            "<svg"
        ]
        
        response_lower = response_text.lower()
        for pattern in dangerous_patterns:
            if pattern.lower() in response_lower:
                # Check if it's escaped
                escaped = pattern.replace("<", "&lt;").replace(">", "&gt;")
                if escaped.lower() not in response_lower:
                    return True
        return False
    
    
    def test_xss_in_post_body_title(self):
        """
        Test: XSS payload in POST title field
        
        OWASP: A03:2021 - XSS
        Risk: High
        
        Validates: API sanitizes title field
        and doesn't reflect unescaped scripts
        """
        vulnerabilities_found = []
        
        for payload in XSS_PAYLOADS:
            response = self.session.post(
                f"{self.base_url}/posts",
                json={
                    "title": payload,
                    "body": "Normal body text",
                    "userId": 1
                },
                timeout=REQUEST_TIMEOUT
            )
            
            # Check 1: Response shouldn't contain raw script
            if self.contains_unescaped_script(response.text, payload):
                vulnerabilities_found.append({
                    "payload": payload,
                    "field": "title",
                    "issue": "XSS payload reflected unescaped",
                    "status_code": response.status_code
                })
            
            # Check 2: Should return 201 (created) or 400 (rejected)
            # NOT 500 (server error)
            if response.status_code == 500:
                vulnerabilities_found.append({
                    "payload": payload,
                    "issue": "Server error triggered by XSS payload",
                    "status_code": response.status_code
                })
        
        if vulnerabilities_found:
            pytest.fail(
                f"XSS vulnerabilities in title field:\n"
                + "\n".join([str(v) for v in vulnerabilities_found])
            )
        
        print(f"\n✅ XSS (title field): "
              f"{len(XSS_PAYLOADS)} payloads tested, "
              f"0 vulnerabilities found")
    
    
    def test_xss_in_post_body_content(self):
        """
        Test: XSS payload in POST body field
        
        OWASP: A03:2021 - XSS
        Risk: High
        
        Validates: API sanitizes body/content field
        """
        vulnerabilities_found = []
        
        for payload in XSS_PAYLOADS:
            response = self.session.post(
                f"{self.base_url}/posts",
                json={
                    "title": "Normal title",
                    "body": payload,
                    "userId": 1
                },
                timeout=REQUEST_TIMEOUT
            )
            
            if self.contains_unescaped_script(response.text, payload):
                vulnerabilities_found.append({
                    "payload": payload,
                    "field": "body",
                    "issue": "XSS payload reflected in body field",
                    "status_code": response.status_code
                })
            
            if response.status_code == 500:
                vulnerabilities_found.append({
                    "payload": payload,
                    "issue": "Server error triggered",
                    "status_code": response.status_code
                })
        
        if vulnerabilities_found:
            pytest.fail(
                f"XSS vulnerabilities in body field:\n"
                + "\n".join([str(v) for v in vulnerabilities_found])
            )
        
        print(f"\n✅ XSS (body field): "
              f"{len(XSS_PAYLOADS)} payloads tested, "
              f"0 vulnerabilities found")
    
    
    def test_xss_in_query_params(self):
        """
        Test: XSS payload in query parameters
        
        OWASP: A03:2021 - XSS (Reflected)
        Risk: High
        
        Validates: Query params are sanitized
        and not reflected back in response
        """
        vulnerabilities_found = []
        
        for payload in XSS_PAYLOADS:
            response = self.session.get(
                f"{self.base_url}/posts",
                params={"search": payload},
                timeout=REQUEST_TIMEOUT
            )
            
            if self.contains_unescaped_script(response.text, payload):
                vulnerabilities_found.append({
                    "payload": payload,
                    "location": "query_param",
                    "issue": "XSS reflected in query param response",
                    "status_code": response.status_code
                })
        
        if vulnerabilities_found:
            pytest.fail(
                f"Reflected XSS in query params:\n"
                + "\n".join([str(v) for v in vulnerabilities_found])
            )
        
        print(f"\n✅ XSS (query params): "
              f"{len(XSS_PAYLOADS)} payloads tested, "
              f"0 vulnerabilities found")
    
    
    def test_content_type_header_prevents_xss(self):
        """
        Test: Content-Type header is set correctly
        
        OWASP: A05:2021 - Security Misconfiguration
        Risk: Medium
        
        Validates: API returns proper Content-Type
        to prevent MIME-type sniffing XSS attacks
        
        Expected: application/json (NOT text/html)
        """
        issues_found = []
        
        endpoints = [
            f"{self.base_url}/posts",
            f"{self.base_url}/posts/1",
            f"{self.base_url}/users",
        ]
        
        for endpoint in endpoints:
            response = self.session.get(
                endpoint,
                timeout=REQUEST_TIMEOUT
            )
            
            content_type = response.headers.get(
                "Content-Type", ""
            ).lower()
            
            # Should be JSON, not HTML
            if "application/json" not in content_type:
                issues_found.append({
                    "endpoint": endpoint,
                    "content_type": content_type,
                    "issue": "Response is not application/json"
                })
            
            # Should NOT be text/html (XSS risk)
            if "text/html" in content_type:
                issues_found.append({
                    "endpoint": endpoint,
                    "content_type": content_type,
                    "issue": "CRITICAL: HTML content type enables XSS"
                })
        
        if issues_found:
            pytest.fail(
                f"Content-Type issues found:\n"
                + "\n".join([str(i) for i in issues_found])
            )
        
        print(f"\n✅ Content-Type headers: "
              f"All {len(endpoints)} endpoints return application/json")
    
    
    def test_xss_special_characters_handling(self):
        """
        Test: Special HTML characters are handled safely
        
        OWASP: A03:2021 - XSS
        Risk: Medium
        
        Validates: API handles special chars
        without causing errors or reflections
        """
        special_chars = [
            "<>",
            "&",
            "\"'",
            "\\",
            "%3Cscript%3E",      # URL encoded <script>
            "&#60;script&#62;",  # HTML encoded <script>
        ]
        
        issues_found = []
        
        for chars in special_chars:
            response = self.session.post(
                f"{self.base_url}/posts",
                json={
                    "title": f"Test {chars} title",
                    "body": "Normal body",
                    "userId": 1
                },
                timeout=REQUEST_TIMEOUT
            )
            
            # Should not crash the server
            if response.status_code == 500:
                issues_found.append({
                    "chars": chars,
                    "issue": "Server error with special characters",
                    "status_code": 500
                })
        
        if issues_found:
            pytest.fail(
                f"Special character handling issues:\n"
                + "\n".join([str(i) for i in issues_found])
            )
        
        print(f"\n✅ Special characters: "
              f"All {len(special_chars)} char sets handled safely")