@"

# Security Testing - OWASP Top 10

![Python](https://img.shields.io/badge/Python-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Pytest](https://img.shields.io/badge/Pytest-0A9EDC?style=for-the-badge&logo=pytest&logoColor=white)
![OWASP](https://img.shields.io/badge/OWASP-000000?style=for-the-badge&logo=owasp&logoColor=white)
![Status](https://img.shields.io/badge/Status-In_Progress-yellow?style=for-the-badge)

> Automated security testing based on OWASP Top 10 vulnerabilities

## 🎯 Project Purpose

Validate API security against the most critical
web application vulnerabilities defined by OWASP.

**API Under Test:** JSONPlaceholder + httpbin.org

## 🚀 Quick Start

\`\`\`bash

# Install dependencies

pip install -r requirements.txt

# Run all security tests

pytest tests/ -v

# Run specific test category

pytest tests/test_sql_injection.py -v
\`\`\`

## 📊 Coverage (Work in Progress)

- [x] SQL Injection (A03:2021)
- [ ] XSS (A03:2021)
- [ ] Security Headers (A05:2021)
- [ ] Authentication (A07:2021)
- [ ] Sensitive Data (A02:2021)
      "@ | Set-Content README.md

## 📊 Running Tests with HTML Report

### Generate Complete Security Report

```bash
# Windows
run_security_tests.bat

# Linux/Mac
./run_security_tests.sh
```

This will:

- Execute all 38 security tests
- Generate timestamped HTML report
- Save to `reports/security_report_YYYYMMDD_HHMMSS.html`

### View Report

The HTML report includes:

- ✅ Test execution summary
- ✅ Pass/Fail status for each test
- ✅ Detailed failure information
- ✅ OWASP category mapping
- ✅ Timestamp and metadata
- ✅ Screenshots of test execution

**Open report:**

```bash
# Windows
start reports\security_report_YYYYMMDD_HHMMSS.html

# macOS
open reports/security_report_YYYYMMDD_HHMMSS.html

# Linux
xdg-open reports/security_report_YYYYMMDD_HHMMSS.html
```

---

## 📋 Test Categories in Report

| Category         | Tests | OWASP    |
| ---------------- | ----- | -------- |
| SQL Injection    | 4     | A03:2021 |
| XSS              | 5     | A03:2021 |
| Security Headers | 7     | A05:2021 |
| Authentication   | 5     | A07:2021 |
| Access Control   | 5     | A01:2021 |
| Sensitive Data   | 7     | A02:2021 |
| Rate Limiting    | 5     | A04:2021 |

**Total:** 38 automated security tests
