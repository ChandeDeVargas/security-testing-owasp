"""
Pytest configuration file
Fixes Unicode encoding issues on Windows
Adds custom report sections
"""
import sys
import io
import pytest
from datetime import datetime

# Fix Unicode encoding for Windows terminal
if sys.platform == "win32":
    sys.stdout = io.TextIOWrapper(
        sys.stdout.buffer,
        encoding='utf-8',
        errors='replace'
    )
    sys.stderr = io.TextIOWrapper(
        sys.stderr.buffer,
        encoding='utf-8',
        errors='replace'
    )


def pytest_html_report_title(report):
    """Customize HTML report title"""
    report.title = "OWASP Security Test Report"


def pytest_configure(config):
    """Add custom metadata to report"""
    config._metadata = {
        "Project": "Security Testing - OWASP Top 10",
        "Tester": "Chande De Vargas",
        "Test Date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "Target API": "JSONPlaceholder (https://jsonplaceholder.typicode.com)",
        "Framework": "Pytest + Requests",
        "Python Version": f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
        "OWASP Coverage": "A01, A02, A03, A04, A05, A07"
    }


def pytest_html_results_summary(prefix, summary, postfix):
    """Add custom summary section to HTML report"""
    prefix.extend([
        "<h2>Security Test Summary</h2>",
        "<p>This report contains automated security tests based on OWASP Top 10 2021.</p>",
        "<p><strong>Test Categories:</strong></p>",
        "<ul>",
        "<li><strong>SQL Injection</strong> - Tests for injection vulnerabilities</li>",
        "<li><strong>XSS</strong> - Cross-Site Scripting tests</li>",
        "<li><strong>Security Headers</strong> - HTTP security header validation</li>",
        "<li><strong>Authentication</strong> - Auth bypass and token validation</li>",
        "<li><strong>Access Control</strong> - IDOR and authorization tests</li>",
        "<li><strong>Sensitive Data</strong> - PII exposure and encryption tests</li>",
        "<li><strong>Rate Limiting</strong> - DoS prevention and abuse tests</li>",
        "</ul>",
        "<p><strong>Note:</strong> Failed tests indicate security vulnerabilities found.</p>"
    ])


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item, call):
    """
    Enhance test report with additional info
    """
    outcome = yield
    report = outcome.get_result()
    
    # Add custom properties to report
    if report.when == "call":
        # Add OWASP category to each test
        test_name = item.nodeid
        
        if "sql_injection" in test_name:
            report.owasp_category = "A03:2021 - Injection"
        elif "xss" in test_name:
            report.owasp_category = "A03:2021 - XSS"
        elif "security_headers" in test_name:
            report.owasp_category = "A05:2021 - Security Misconfiguration"
        elif "authentication" in test_name:
            report.owasp_category = "A07:2021 - Auth Failures"
        elif "access_control" in test_name:
            report.owasp_category = "A01:2021 - Broken Access Control"
        elif "sensitive_data" in test_name:
            report.owasp_category = "A02:2021 - Cryptographic Failures"
        elif "rate_limiting" in test_name:
            report.owasp_category = "A04:2021 - Insecure Design"
        else:
            report.owasp_category = "General Security"