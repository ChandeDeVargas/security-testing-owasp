"""
OWASP A02:2021 - Cryptographic Failures
Sensitive Data Exposure Tests

Purpose: Validate that API properly protects
sensitive data from unauthorized exposure.

Tests:
- PII data exposure
- Data minimization
- Sensitive fields in responses
- Error message information leakage
- Debug information exposure
"""
import pytest
import requests
import re
from config import (
    BASE_URL,
    REQUEST_TIMEOUT
)


class TestSensitiveData:
    """
    Sensitive Data Exposure test suite.
    
    Tests that API:
    1. Doesn't expose unnecessary PII
    2. Masks sensitive fields
    3. Doesn't leak internal info in errors
    4. Follows data minimization principles
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
    
    
    def test_pii_exposure_in_user_responses(self):
        """
        Test: Check PII exposure in user responses
        
        OWASP: A02:2021 - Cryptographic Failures
        Risk: High
        
        Purpose: Identify what PII is exposed
        and whether it's necessary.
        
        PII Fields: name, email, phone, address
        """
        response = self.session.get(
            f"{self.base_url}/users/1",
            timeout=REQUEST_TIMEOUT
        )
        
        assert response.status_code == 200
        user_data = response.json()
        
        # Catalog all PII fields found
        pii_fields = {
            "name": user_data.get("name"),
            "email": user_data.get("email"),
            "phone": user_data.get("phone"),
            "address": user_data.get("address"),
            "website": user_data.get("website"),
            "company": user_data.get("company")
        }
        
        exposed_pii = {
            k: v for k, v in pii_fields.items() if v
        }
        
        print(f"\n[PII Audit] Fields exposed in /users/1:")
        for field, value in exposed_pii.items():
            print(f"  {field}: {str(value)[:50]}")
        
        # Check for highly sensitive fields
        critical_pii = []
        
        if user_data.get("phone"):
            critical_pii.append(
                f"phone: {user_data['phone']}"
            )
        
        if user_data.get("address"):
            addr = user_data["address"]
            critical_pii.append(
                f"address: {addr.get('street')}, "
                f"{addr.get('city')}, {addr.get('zipcode')}"
            )
        
        if critical_pii:
            pytest.fail(
                f"SENSITIVE PII EXPOSED without authentication:\n"
                + "\n".join([f"  - {p}" for p in critical_pii])
                + f"\n\nTotal PII fields exposed: {len(exposed_pii)}"
                + f"\nFix: Require authentication for user data"
            )
        
        print(f"\n[PASS] PII exposure within acceptable limits")
    
    
    def test_email_pattern_in_responses(self):
        """
        Test: Email addresses exposed in bulk responses
        
        OWASP: A02:2021 - Cryptographic Failures
        Risk: High
        
        Purpose: Check if email addresses are
        exposed in list endpoints (bulk harvesting risk)
        """
        response = self.session.get(
            f"{self.base_url}/users",
            timeout=REQUEST_TIMEOUT
        )
        
        assert response.status_code == 200
        
        # Find all email patterns in response
        email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        emails_found = re.findall(
            email_pattern,
            response.text
        )
        
        print(f"\n[Email Audit] Emails found in /users response:")
        for email in emails_found:
            print(f"  - {email}")
        
        if len(emails_found) > 0:
            pytest.fail(
                f"EMAIL EXPOSURE: {len(emails_found)} email addresses "
                f"found in unauthenticated /users response\n"
                f"Risk: Bulk email harvesting for phishing/spam\n"
                f"Emails found: {emails_found[:5]}"
            )
        
        print(f"\n[PASS] No email addresses exposed in bulk response")
    
    
    def test_geolocation_data_exposed(self):
        """
        Test: GPS/geolocation data exposed
        
        OWASP: A02:2021 - Cryptographic Failures
        Risk: High
        
        Purpose: GPS coordinates are highly sensitive PII.
        They reveal exact physical locations of users.
        """
        response = self.session.get(
            f"{self.base_url}/users/1",
            timeout=REQUEST_TIMEOUT
        )
        
        assert response.status_code == 200
        user_data = response.json()
        
        # Check for geolocation data
        geo_data = user_data.get("address", {}).get("geo", {})
        
        if geo_data:
            lat = geo_data.get("lat")
            lng = geo_data.get("lng")
            
            if lat and lng:
                pytest.fail(
                    f"GEOLOCATION EXPOSED:\n"
                    f"  Latitude: {lat}\n"
                    f"  Longitude: {lng}\n"
                    f"  User: {user_data.get('name')}\n"
                    f"  Risk: Exact physical location revealed\n"
                    f"  Fix: Remove geo data or require auth"
                )
        
        print(f"\n[PASS] No geolocation data exposed")
    
    
    def test_sensitive_data_in_error_responses(self):
        """
        Test: Error responses don't leak sensitive info
        
        OWASP: A02:2021 - Cryptographic Failures
        Risk: Medium
        
        Purpose: Error messages should be generic
        and not reveal internal implementation details
        """
        # Trigger various error conditions
        error_endpoints = [
            f"{self.base_url}/users/99999",
            f"{self.base_url}/posts/99999",
            f"{self.base_url}/nonexistent",
        ]
        
        sensitive_patterns = [
            r"password",
            r"secret",
            r"token",
            r"key",
            r"database",
            r"sql",
            r"exception",
            r"traceback",
            r"stack",
            r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}",  # IP addresses
            r"mongodb://",
            r"mysql://",
            r"postgres://"
        ]
        
        exposures = []
        
        for endpoint in error_endpoints:
            response = self.session.get(
                endpoint,
                timeout=REQUEST_TIMEOUT
            )
            
            for pattern in sensitive_patterns:
                if re.search(pattern, response.text, re.IGNORECASE):
                    exposures.append({
                        "endpoint": endpoint,
                        "pattern": pattern,
                        "status": response.status_code,
                        "response": response.text[:100]
                    })
        
        if exposures:
            pytest.fail(
                f"Sensitive data in error responses:\n"
                + "\n".join([str(e) for e in exposures])
            )
        
        print(f"\n[PASS] Error responses don't expose sensitive data")
    
    
    def test_response_data_minimization(self):
        """
        Test: API returns only necessary data
        
        OWASP: A02:2021 - Cryptographic Failures
        Risk: Medium
        
        Purpose: Check if API follows data minimization
        principle (only return what's needed)
        
        Red flags: Internal IDs, audit fields,
        system metadata in responses
        """
        response = self.session.get(
            f"{self.base_url}/users/1",
            timeout=REQUEST_TIMEOUT
        )
        
        assert response.status_code == 200
        user_data = response.json()
        
        # Fields that should NOT be in a public API response
        suspicious_fields = [
            "password",
            "password_hash",
            "salt",
            "secret",
            "token",
            "api_key",
            "ssn",
            "credit_card",
            "bank_account",
            "created_at",
            "updated_at",
            "deleted_at",
            "internal_id",
            "admin",
        ]
        
        found_suspicious = []
        
        for field in suspicious_fields:
            if field in user_data:
                found_suspicious.append({
                    "field": field,
                    "value": str(user_data[field])[:30]
                })
        
        if found_suspicious:
            pytest.fail(
                f"Suspicious fields in response:\n"
                + "\n".join([str(f) for f in found_suspicious])
            )
        
        print(f"\n[PASS] No suspicious fields in user response")
        print(f"  Fields returned: {list(user_data.keys())}")
    
    
    def test_https_enforced(self):
        """
        Test: API enforces HTTPS (not HTTP)
        
        OWASP: A02:2021 - Cryptographic Failures
        Risk: High
        
        Purpose: HTTP transmits data in plaintext.
        API should redirect or reject HTTP requests.
        """
        # Try HTTP version of the API
        http_url = BASE_URL.replace("https://", "http://")
        
        issues = []
        
        try:
            response = self.session.get(
                f"{http_url}/posts/1",
                timeout=REQUEST_TIMEOUT,
                allow_redirects=False
            )
            
            # Should redirect to HTTPS (301/302)
            # or reject (400/403)
            if response.status_code == 200:
                issues.append(
                    f"API accessible via HTTP (no redirect)\n"
                    f"URL: {http_url}/posts/1\n"
                    f"Status: {response.status_code}\n"
                    f"Risk: Data transmitted in plaintext"
                )
            elif response.status_code in [301, 302, 307, 308]:
                location = response.headers.get("Location", "")
                if "https://" in location:
                    print(f"\n[PASS] HTTP redirects to HTTPS: {location}")
                else:
                    issues.append(
                        f"HTTP redirect doesn't go to HTTPS\n"
                        f"Location: {location}"
                    )
        except Exception as e:
            print(f"\n[PASS] HTTP connection refused: {str(e)[:50]}")
        
        if issues:
            pytest.fail("\n".join(issues))
    
    
    def test_internal_ip_not_exposed(self):
        """
        Test: Internal IP addresses not exposed
        
        OWASP: A05:2021 - Security Misconfiguration
        Risk: Medium
        
        Purpose: Internal IPs in headers or responses
        help attackers map internal network topology
        """
        response = self.session.get(
            f"{self.base_url}/posts/1",
            timeout=REQUEST_TIMEOUT
        )
        
        # Check headers for internal IPs
        ip_pattern = r'\b(?:10|172\.(?:1[6-9]|2\d|3[01])|192\.168)\.\d{1,3}\.\d{1,3}\b'
        
        exposures = []
        
        # Check response headers
        for header_name, header_value in response.headers.items():
            if re.search(ip_pattern, header_value):
                exposures.append(
                    f"Internal IP in header {header_name}: {header_value}"
                )
        
        # Check response body
        if re.search(ip_pattern, response.text):
            exposures.append(
                f"Internal IP in response body"
            )
        
        if exposures:
            pytest.fail(
                f"Internal IP addresses exposed:\n"
                + "\n".join(exposures)
            )
        
        print(f"\n[PASS] No internal IP addresses exposed")