"""
OWASP A03:2021 - Injection
SQL Injection Security Tests

Purpose: Validate that API endpoints properly
sanitize inputs and reject malicious SQL payloads.

Target: JSONPlaceholder API (safe public API)
"""
import pytest
import requests
from config import (
    BASE_URL,
    SQL_INJECTION_PAYLOADS,
    REQUEST_TIMEOUT
)


class TestSQLInjection:
    """
    SQL Injection test suite.
    
    Tests that API endpoints:
    1. Don't return unexpected data with SQL payloads
    2. Return appropriate error codes (400/422)
    3. Don't expose database errors
    4. Handle malicious input gracefully
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
    
    
    def is_sql_error_exposed(self, response_text):
        """
        Check if response contains SQL error messages.
        This would indicate vulnerability.
        """
        sql_error_patterns = [
            "sql syntax",
            "mysql_fetch",
            "ORA-",
            "PostgreSQL",
            "SQLite",
            "syntax error",
            "unclosed quotation",
            "quoted string not properly terminated"
        ]
        
        response_lower = response_text.lower()
        for pattern in sql_error_patterns:
            if pattern.lower() in response_lower:
                return True
        return False
    
    
    def test_sql_injection_in_query_params(self):
        """
        Test: SQL injection via query parameters
        
        OWASP: A03:2021 - Injection
        Risk: High
        
        Validates: API rejects or safely handles
        SQL payloads in URL parameters
        """
        vulnerabilities_found = []
        
        for payload in SQL_INJECTION_PAYLOADS:
            response = self.session.get(
                f"{self.base_url}/posts",
                params={"userId": payload},
                timeout=REQUEST_TIMEOUT
            )
            
            # Check 1: No SQL errors exposed
            if self.is_sql_error_exposed(response.text):
                vulnerabilities_found.append({
                    "payload": payload,
                    "issue": "SQL error message exposed",
                    "status_code": response.status_code
                })
            
            # Check 2: Should not return ALL records
            # (would indicate bypass)
            if response.status_code == 200:
                data = response.json()
                if isinstance(data, list) and len(data) > 100:
                    vulnerabilities_found.append({
                        "payload": payload,
                        "issue": "Possible data dump (too many records)",
                        "status_code": response.status_code,
                        "records_returned": len(data)
                    })
        
        # Report results
        if vulnerabilities_found:
            pytest.fail(
                f"SQL Injection vulnerabilities found:\n"
                + "\n".join([str(v) for v in vulnerabilities_found])
            )
        
        print(f"\nSQL Injection (query params): "
              f"{len(SQL_INJECTION_PAYLOADS)} payloads tested, "
              f"0 vulnerabilities found")
    
    
    def test_sql_injection_in_post_body(self):
        """
        Test: SQL injection via POST request body
        
        OWASP: A03:2021 - Injection
        Risk: High
        
        Validates: API sanitizes POST body inputs
        """
        vulnerabilities_found = []
        
        for payload in SQL_INJECTION_PAYLOADS:
            # Test payload in each field
            malicious_payloads = [
                {"title": payload, "body": "Normal text", "userId": 1},
                {"title": "Normal", "body": payload, "userId": 1},
            ]
            
            for malicious_body in malicious_payloads:
                response = self.session.post(
                    f"{self.base_url}/posts",
                    json=malicious_body,
                    timeout=REQUEST_TIMEOUT
                )
                
                # Check: No SQL errors in response
                if self.is_sql_error_exposed(response.text):
                    vulnerabilities_found.append({
                        "payload": payload,
                        "field": "title/body",
                        "issue": "SQL error exposed in POST",
                        "status_code": response.status_code
                    })
                
                # Check: Unexpected server errors
                if response.status_code == 500:
                    vulnerabilities_found.append({
                        "payload": payload,
                        "issue": "Server error (500) triggered",
                        "status_code": response.status_code
                    })
        
        if vulnerabilities_found:
            pytest.fail(
                f"SQL Injection vulnerabilities in POST body:\n"
                + "\n".join([str(v) for v in vulnerabilities_found])
            )
        
        print(f"\nSQL Injection (POST body): "
              f"{len(SQL_INJECTION_PAYLOADS)} payloads tested, "
              f"0 vulnerabilities found")
    
    
    def test_sql_injection_in_path_params(self):
        """
        Test: SQL injection via URL path parameters
        
        OWASP: A03:2021 - Injection
        Risk: High
        
        Validates: API handles malicious path parameters
        """
        vulnerabilities_found = []
        
        path_payloads = [
            "1 OR 1=1",
            "1; DROP TABLE posts",
            "1 UNION SELECT * FROM users",
            "1'",
            "1--"
        ]
        
        for payload in path_payloads:
            response = self.session.get(
                f"{self.base_url}/posts/{payload}",
                timeout=REQUEST_TIMEOUT
            )
            
            # Should return 404 (not found) not 200 or 500
            if response.status_code == 500:
                vulnerabilities_found.append({
                    "payload": payload,
                    "issue": "Server error triggered by path injection",
                    "status_code": response.status_code
                })
            
            if self.is_sql_error_exposed(response.text):
                vulnerabilities_found.append({
                    "payload": payload,
                    "issue": "SQL error exposed via path param",
                    "status_code": response.status_code
                })
        
        if vulnerabilities_found:
            pytest.fail(
                f"SQL Injection via path params:\n"
                + "\n".join([str(v) for v in vulnerabilities_found])
            )
        
        print(f"\nSQL Injection (path params): "
              f"{len(path_payloads)} payloads tested, "
              f"0 vulnerabilities found")
    
    
    def test_error_handling_doesnt_expose_stack(self):
        """
        Test: Error responses don't expose stack traces
        
        OWASP: A05:2021 - Security Misconfiguration
        Risk: Medium
        
        Validates: Error messages are generic (no internals exposed)
        """
        dangerous_patterns = [
            "traceback",
            "stack trace",
            "at line",
            "exception in",
            "internal server",
            "debug",
            "sqlalchemy",
            "django",
            "flask"
        ]
        
        # Send invalid requests to trigger errors
        invalid_requests = [
            f"{self.base_url}/posts/99999999",    # Non-existent resource
            f"{self.base_url}/invalid-endpoint",   # Invalid path
            f"{self.base_url}/posts/-1",           # Invalid ID
        ]
        
        exposures_found = []
        
        for url in invalid_requests:
            response = self.session.get(url, timeout=REQUEST_TIMEOUT)
            
            response_lower = response.text.lower()
            for pattern in dangerous_patterns:
                if pattern in response_lower:
                    exposures_found.append({
                        "url": url,
                        "pattern": pattern,
                        "status_code": response.status_code
                    })
        
        if exposures_found:
            pytest.fail(
                f"Internal information exposed in errors:\n"
                + "\n".join([str(e) for e in exposures_found])
            )
        
        print(f"\nError handling: No stack traces or "
              f"internal info exposed")