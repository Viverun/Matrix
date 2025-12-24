# Security Scan Report

**Target:** http://example.com  
**Generated:** 2025-12-24T18:10:33.651542  
**Scanner:** Matrix Security Scanner v2.0

---

## Executive Summary

The security scan identified 3 vulnerabilities, including 1 CRITICAL and 1 HIGH severity findings that require immediate attention.

### Statistics

| Severity | Count |
|----------|-------|
| Critical | 1 |
| High     | 1 |
| Medium   | 1 |
| Low      | 0 |
| Info     | 0 |
| **Total** | **3** |

**High Confidence Findings:** 3  
**Average Confidence:** 89.3%

---

## Detailed Findings


### CRITICAL Severity

#### 1. SQL Injection in 'id' parameter

**Severity:** CRITICAL  
**CVSS Score:** 9.8 (Critical)  
**Vector:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`  
**Confidence:** 95.0%  
**Location:** `GET http://example.com/api/users`  
**Parameter:** `id`  

**Description:**  
An error-based SQL injection vulnerability allows attackers to execute arbitrary SQL queries.

**Evidence:**
```
MySQL error: 'You have an error in your SQL syntax near '1'='1''
```

**Proof of Concept:**
```json
{
  "params": {
    "id": "' OR '1'='1"
  }
}
```

**Remediation:**  
Use parameterized queries (prepared statements) instead of string concatenation.

**Standards Mapping:**
- **OWASP:** A03:2021 – Injection
- **CWE:** CWE-89

**References:**
- https://owasp.org/Top10/A03_2021-Injection/
- https://portswigger.net/web-security/sql-injection

**Detected by:** sql_injection

---


### HIGH Severity

#### 1. Reflected XSS in search parameter

**Severity:** HIGH  
**CVSS Score:** 5.3 (Medium)  
**Vector:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N`  
**Confidence:** 88.0%  
**Location:** `GET http://example.com/search`  
**Parameter:** `q`  

**Description:**  
User input is reflected in HTML without proper encoding, allowing script injection.

**Evidence:**
```
Payload <script>alert('XSS')</script> was reflected unencoded in response.
```

**Proof of Concept:**
```json
{
  "params": {
    "q": "<script>alert('XSS')</script>"
  }
}
```

**Remediation:**  
HTML-encode all user input before rendering in web pages. Use Content-Security-Policy header.

**Standards Mapping:**
- **OWASP:** A03:2021 – Injection
- **CWE:** CWE-79

**References:**
- https://owasp.org/Top10/A03_2021-Injection/

**Detected by:** xss

---


### MEDIUM Severity

#### 1. Missing CSRF protection on profile update

**Severity:** MEDIUM  
**CVSS Score:** 7.1 (High)  
**Vector:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:H/A:N`  
**Confidence:** 85.0%  
**Location:** `POST http://example.com/api/profile/update`  

**Description:**  
State-changing operation lacks CSRF tokens, allowing cross-site request forgery.

**Evidence:**
```
POST request succeeded without CSRF token or SameSite cookie attribute.
```

**Proof of Concept:**
```json
{
  "data": {
    "email": "attacker@example.com"
  }
}
```

**Remediation:**  
Implement synchronizer tokens pattern. Set SameSite=Strict on session cookies.

**Standards Mapping:**
- **OWASP:** A01:2021 – Broken Access Control
- **CWE:** CWE-352

**References:**
- https://owasp.org/Top10/A01_2021-Broken_Access_Control/

**Detected by:** csrf

---

