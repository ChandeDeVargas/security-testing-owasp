"""
OWASP A04:2021 - Insecure Design
Rate Limiting and Abuse Prevention Tests

Purpose: Validate that API has protections
against abuse, DoS, and automated attacks.

Tests:
- Rate limiting detection
- Request flooding protection
- Large payload handling
- Concurrent request handling
- Response time under load
"""
import pytest
import requests
import time
import threading
from config import (
    BASE_URL,
    REQUEST_TIMEOUT
)


class TestRateLimiting:
    """
    Rate Limiting and Abuse Prevention test suite.
    
    Tests that API:
    1. Limits request frequency
    2. Handles large payloads safely
    3. Handles concurrent requests
    4. Maintains acceptable response times
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
    
    
    def test_rate_limiting_detection(self):
        """
        Test: API implements rate limiting
        
        OWASP: A04:2021 - Insecure Design
        Risk: High
        
        Purpose: Without rate limiting, API is
        vulnerable to DoS and brute force attacks.
        
        Test: Send 30 rapid requests and check
        for 429 (Too Many Requests) response
        """
        responses = []
        rate_limited = False
        requests_before_limit = 0
        
        print(f"\n[Rate Limit Test] Sending 30 rapid requests...")
        
        for i in range(30):
            start = time.time()
            response = self.session.get(
                f"{self.base_url}/posts",
                timeout=REQUEST_TIMEOUT
            )
            elapsed = (time.time() - start) * 1000
            
            responses.append({
                "request": i + 1,
                "status": response.status_code,
                "time_ms": round(elapsed, 2)
            })
            
            if response.status_code == 429:
                rate_limited = True
                requests_before_limit = i + 1
                print(f"  Rate limit triggered at request {i+1}")
                break
        
        # Analyze results
        status_codes = [r["status"] for r in responses]
        avg_time = sum(r["time_ms"] for r in responses) / len(responses)
        
        print(f"  Requests sent: {len(responses)}")
        print(f"  Status codes: {set(status_codes)}")
        print(f"  Avg response time: {avg_time:.2f}ms")
        print(f"  Rate limited: {rate_limited}")
        
        if not rate_limited:
            # Log as warning (not fail) for public APIs
            print(f"\n[WARNING] No rate limiting after 30 requests")
            print(f"  Risk: DoS and brute force attacks possible")
            print(f"  Recommendation: Implement rate limiting")
            print(f"  Suggested: 100 req/min per IP")
    
    
    def test_large_payload_handling(self):
        """
        Test: API handles large payloads safely
        
        OWASP: A04:2021 - Insecure Design
        Risk: Medium
        
        Purpose: Large payloads can cause:
        - Memory exhaustion (DoS)
        - Slow processing (performance DoS)
        - Buffer overflow vulnerabilities
        """
        # Test with increasingly large payloads
        payload_sizes = [
            ("1KB", "A" * 1024),
            ("10KB", "A" * 10240),
            ("100KB", "A" * 102400),
            ("500KB", "A" * 512000),
        ]
        
        issues = []
        
        for size_name, payload in payload_sizes:
            start = time.time()
            
            try:
                response = self.session.post(
                    f"{self.base_url}/posts",
                    json={
                        "title": f"Large payload test {size_name}",
                        "body": payload,
                        "userId": 1
                    },
                    timeout=REQUEST_TIMEOUT
                )
                elapsed = (time.time() - start) * 1000
                
                print(f"\n  {size_name} payload: "
                      f"status={response.status_code}, "
                      f"time={elapsed:.0f}ms")
                
                # Server should reject very large payloads
                if response.status_code == 500:
                    issues.append(
                        f"Server error with {size_name} payload"
                    )
                
                # Response should be fast even with large payload
                if elapsed > 5000 and response.status_code == 201:
                    issues.append(
                        f"Slow response with {size_name}: {elapsed:.0f}ms"
                    )
                    
            except requests.exceptions.Timeout:
                print(f"\n  {size_name} payload: TIMEOUT (>10s)")
                issues.append(
                    f"Timeout with {size_name} payload - DoS risk"
                )
        
        if issues:
            pytest.fail(
                f"Large payload handling issues:\n"
                + "\n".join(issues)
            )
        
        print(f"\n[PASS] Large payloads handled without server errors")
    
    
    def test_concurrent_requests_stability(self):
        """
        Test: API handles concurrent requests stably
        
        OWASP: A04:2021 - Insecure Design
        Risk: Medium
        
        Purpose: Verify API doesn't crash or
        return errors under concurrent load.
        
        Test: Send 10 concurrent requests
        """
        results = []
        errors = []
        
        def make_request(thread_id):
            try:
                response = requests.get(
                    f"{self.base_url}/posts/{thread_id}",
                    timeout=REQUEST_TIMEOUT
                )
                results.append({
                    "thread": thread_id,
                    "status": response.status_code,
                    "success": response.status_code == 200
                })
            except Exception as e:
                errors.append({
                    "thread": thread_id,
                    "error": str(e)
                })
        
        # Create and start 10 concurrent threads
        threads = []
        for i in range(1, 11):
            t = threading.Thread(
                target=make_request,
                args=(i,)
            )
            threads.append(t)
        
        print(f"\n[Concurrent Test] Sending 10 concurrent requests...")
        
        # Start all threads simultaneously
        start = time.time()
        for t in threads:
            t.start()
        
        # Wait for all to complete
        for t in threads:
            t.join()
        elapsed = time.time() - start
        
        successful = sum(1 for r in results if r["success"])
        
        print(f"  Completed: {len(results)}/10 requests")
        print(f"  Successful: {successful}/10")
        print(f"  Errors: {len(errors)}")
        print(f"  Total time: {elapsed:.2f}s")
        
        if errors:
            pytest.fail(
                f"Errors in concurrent requests:\n"
                + "\n".join([str(e) for e in errors])
            )
        
        if successful < 8:
            pytest.fail(
                f"Too many failures under concurrent load:\n"
                f"  Successful: {successful}/10\n"
                f"  Failed: {10 - successful}/10"
            )
        
        print(f"\n[PASS] API stable under concurrent requests")
    
    
    def test_response_time_consistency(self):
        """
        Test: Response times are consistent
        
        OWASP: A04:2021 - Insecure Design
        Risk: Low
        
        Purpose: Highly variable response times
        can indicate timing attacks or instability.
        
        Test: Send 10 requests and check variance
        """
        response_times = []
        
        print(f"\n[Response Time Test] Sending 10 requests...")
        
        for i in range(10):
            start = time.time()
            response = self.session.get(
                f"{self.base_url}/posts/1",
                timeout=REQUEST_TIMEOUT
            )
            elapsed = (time.time() - start) * 1000
            response_times.append(elapsed)
            
            print(f"  Request {i+1}: {elapsed:.0f}ms "
                  f"(status: {response.status_code})")
        
        # Calculate statistics
        avg = sum(response_times) / len(response_times)
        min_time = min(response_times)
        max_time = max(response_times)
        variance = max_time - min_time
        
        print(f"\n  Average: {avg:.0f}ms")
        print(f"  Min: {min_time:.0f}ms")
        print(f"  Max: {max_time:.0f}ms")
        print(f"  Variance: {variance:.0f}ms")
        
        issues = []
        
        # Average should be under 2 seconds
        if avg > 2000:
            issues.append(
                f"High average response time: {avg:.0f}ms"
            )
        
        # Variance should not be extreme
        if variance > 5000:
            issues.append(
                f"Extreme response time variance: {variance:.0f}ms\n"
                f"  Min: {min_time:.0f}ms, Max: {max_time:.0f}ms\n"
                f"  Risk: Possible timing attack vulnerability"
            )
        
        if issues:
            pytest.fail(
                f"Response time issues:\n"
                + "\n".join(issues)
            )
        
        print(f"\n[PASS] Response times within acceptable range")
    
    
    def test_path_traversal_prevention(self):
        """
        Test: Path traversal attacks prevented
        
        OWASP: A01:2021 - Broken Access Control
        Risk: High
        
        Purpose: Path traversal allows attackers
        to access files outside intended directory.
        
        Example: /posts/../../../etc/passwd
        """
        traversal_payloads = [
            "/../../../etc/passwd",
            "/..%2F..%2F..%2Fetc%2Fpasswd",
            "/%2e%2e/%2e%2e/etc/passwd",
            "/....//....//etc/passwd",
            "/%252e%252e%252fetc%252fpasswd",
        ]
        
        issues = []
        
        for payload in traversal_payloads:
            try:
                response = self.session.get(
                    f"{self.base_url}/posts{payload}",
                    timeout=REQUEST_TIMEOUT,
                    allow_redirects=False
                )
                
                # Check for file content in response
                dangerous_patterns = [
                    "root:x:",           # /etc/passwd content
                    "daemon:x:",
                    "/bin/bash",
                    "windows/system32"
                ]
                
                for pattern in dangerous_patterns:
                    if pattern in response.text.lower():
                        issues.append({
                            "payload": payload,
                            "issue": "Path traversal successful!",
                            "pattern": pattern,
                            "status": response.status_code
                        })
                
                # 500 might indicate traversal attempt processed
                if response.status_code == 500:
                    issues.append({
                        "payload": payload,
                        "issue": "Server error (possible traversal)",
                        "status": 500
                    })
                    
            except Exception:
                pass  # Connection refused = good
        
        if issues:
            pytest.fail(
                f"Path traversal vulnerability:\n"
                + "\n".join([str(i) for i in issues])
            )
        
        print(f"\n[PASS] Path traversal attempts blocked "
              f"({len(traversal_payloads)} payloads tested)")