# Matrix Security Scanner - Agent Documentation

## Overview

Matrix uses specialized **agents** to detect different types of security vulnerabilities. Each agent is an expert in finding specific vulnerability types. This document explains how each agent works in simple terms.

---

## 🎯 How Agents Work Together

When you scan a target URL, the **Orchestrator** coordinates multiple agents:

1. **Discovery Phase**: GitHub Agent analyzes repository code (if it's a GitHub URL)
2. **Reconnaissance Phase**: All agents gather information about the target
3. **Active Scanning Phase**: Each agent tests for specific vulnerabilities
4. **Analysis Phase**: Agents correlate findings and eliminate false positives
Great idea! Let's verify the agents are working correctly with the lazy loading fixes. I'll help you test this on your production server.

Testing Plan:

Navigate to your deployed frontend (Vercel)
Start a scan on the vulnerable demo site: https://pentest-ground.com:4280
Monitor the scan to verify:
Agents load on-demand (check Render logs)
All agents execute successfully
Vulnerabilities are detected correctly
Memory stays under control
Quick Test:

Would you like me to:

Open the browser to your production site and start a scan, or
Check the Render logs to see if the latest deployment is running with the fixes?
The new pre-scan warning modal should appear when you click "Scan" for the first time. You can click "Start Demo Scan Now" to automatically test against the vulnerable site, or proceed with a custom URL.

Which would you prefer? I can help you navigate through either option! 🎯


### Agent Dependencies

Some agents depend on others to run first:
- **SQL Injection**, **XSS**, **CSRF**, **SSRF**, **Command Injection** → Depend on **Auth Agent** and **API Agent** to discover endpoints and login pages

---

## 1. SQL Injection Agent

### What It Does
Detects SQL injection vulnerabilities where attackers can manipulate database queries.

### How It Works

#### **No Specific URL Required** ✅
- Works with **any URL** you provide
- Automatically discovers and tests parameters in endpoints
- Tests common login endpoints automatically

#### Detection Techniques

**1. Error-Based Detection** (Fastest)
- Injects payloads like `' OR 1=1--` into parameters
- Looks for database error messages in responses
- Matches patterns like:
  - `SQL syntax error`
  - `MySQL error`
  - `PostgreSQL ERROR`

**2. Boolean-Based Blind Detection** (Medium Speed)
- Sends two payloads: one "true" (`' AND '1'='1`) and one "false" (` ' AND '1'='2`)
- Compares response differences
- If responses differ significantly → vulnerability exists

**3. Time-Based Blind Detection** (Slowest)
- Injects commands like `'; SLEEP(5)--`
- Measures response time
- If response delays by ~5 seconds → vulnerable

#### Smart Features
- **Database Detection**: Automatically detects MySQL, PostgreSQL, MSSQL, Oracle, or SQLite
- **Targeted Payloads**: Uses database-specific payloads (e.g., `SLEEP()` for MySQL, `pg_sleep()` for PostgreSQL)
- **Login Bypass Testing**: Automatically tests endpoints like `/api/login`, `/rest/user/loginGreat idea! Let's verify the agents are working correctly with the lazy loading fixes. I'll help you test this on your production server.

Testing Plan:

Navigate to your deployed frontend (Vercel)
Start a scan on the vulnerable demo site: https://pentest-ground.com:4280
Monitor the scan to verify:
Agents load on-demand (check Render logs)
All agents execute successfullyGreat idea! Let's verify the agents are working correctly with the lazy loading fixes. I'll help you test this on your production server.

Testing Plan:

Navigate to your deployed frontend (Vercel)
Start a scan on the vulnerable demo site: https://pentest-ground.com:4280
Monitor the scan to verify:
Agents load on-demand (check Render logs)
All agents execute successfully
Vulnerabilities are detected correctly
Memory stays under control
Quick Test:

Would you like me to:

Open the browser to your production site and start a scan, or
Check the Render logs to see if the latest deployment is running with the fixes?
The new pre-scan warning modal should appear when you click "Scan" for the first time. You can click "Start Demo Scan Now" to automatically test against the vulnerable site, or proceed with a custom URL.

Which would you prefer? I can help you navigate through either option! 🎯
Vulnerabilities are detected correctly
Memory stays under control
Quick Test:

Would you like me to:

Open the browser to your production site and start a scan, or
Check the Render logs to see if the latest deployment is running with the fixes?
The new pre-scan warning modal should appear when you click "Scan" for the first time. You can click "Start Demo Scan Now" to automatically test against the vulnerable site, or proceed with a custom URL.

Which would you prefer? I can help you navigate through either option! 🎯` with bypass payloads

---

## 2. Cross-Site Scripting (XSS) Agent

### What It Does
Detects XSS vulnerabilities where attackers can inject malicious JavaScript into web pages.

### How It Works

#### Detection Techniques

**1. Reflected XSS**
- Injects unique markers like `MATRIX_XSS_TEST_12345`
- Detects the **context** where input is reflected (HTML body, HTML attribute, JavaScript, URL, CSS)
- Uses context-specific payloads:
  - **HTML Body**: `<script>alert('XSS')</script>`
  - **HTML Attribute**: `" onmouseover="alert('XSS')"`
  - **JavaScript**: `';alert('XSS');//`

**2. Stored XSS**
- Tests POST/PUT endpoints
- Stores payloads, then retrieves them later
- Checks if payload persists in responses

**3. DOM-Based XSS**
- Analyzes JavaScript code for dangerous data flows
- Traces sources (like `location.search`) to sinks (like `innerHTML`)
- Example: `var x = location.hash; element.innerHTML = x;` → Vulnerable!

#### Smart Features
- **Framework Detection**: Uses specific payloads for React, Vue.js, Angular, jQuery
- **CSP Analysis**: Checks Content Security Policy headers and suggests bypass techniques
- **Mutation XSS Detection**: Detects XSS that occurs during HTML parsing

---

## 3. Authentication Agent

### What It Does
Tests for authentication and session management vulnerabilities.

### How It Works

#### What It Tests

**1. Default Credentials**
- Tests common credentials like `admin:admin`, `admin:password`, `root:root`
- Checks for success indicators (`dashboard`, `logout`, `welcome`)
- Looks for session cookies

**2. Username Enumeration (Error-Based)**
- Tests valid vs invalid usernames
- Compares error messages
- Detects patterns like:
  - `"user not found"` → Reveals username doesn't exist
  - `"incorrect password"` → Reveals username exists

**3. Username Enumeration (Timing-Based)**
- Measures response time for valid vs invalid usernames
- If timing differs significantly (>150ms) → vulnerable

**4. Rate Limiting**
- Sends 15 rapid login attempts
- Checks if requests are blocked or throttled
- If all succeed → Missing rate limiting

**5. Weak Password Policies**
- Tries registering with weak passwords like `123456`
- If accepted → Weak password policy

**6. Session Security**
- Checks session token length (minimum 16 characters)
- Verifies tokens aren't exposed in URLs
- Checks for secure session regeneration

---

## 4. CSRF (Cross-Site Request Forgery) Agent

### What It Does
Detects missing or weak CSRF protection on state-changing endpoints.

### How It Works

#### Detection Process

**1. Identifies State-Changing Endpoints**
- Focuses on POST, PUT, DELETE, PATCH methods
- These modify server state and need CSRF protection

**2. Analyzes Protection Mechanisms**
Checks for:
- **Synchronizer tokens**: Hidden fields in forms
- **Double-submit cookies**: Token in both cookie and request
- **Custom headers**: X-CSRF-Token header requirement
- **SameSite cookies**: Cookie attribute that blocks cross-site requests

**3. Tests Token Bypass Techniques**
- Removes token completely
- Sends empty token
- Sends invalid/manipulated token
- If request still succeeds → Bypass found!

**4. Checks Token Strength**
- Calculates entropy (randomness)
- Checks length (minimum 16 characters)
- Detects patterns (sequential, timestamp-based, MD5 hash)

---

## 5. SSRF (Server-Side Request Forgery) Agent

### What It Does
Detectsvulnerabilities where the server makes requests to internal resources on behalf of the attacker.

### How It Works

#### What It Tests (In Priority Order)

**1. Cloud Metadata Access** (CRITICAL)
- Tests AWS: `http://169.254.169.254/latest/meta-data/`
- Tests GCP: `http://metadata.google.internal/`
- Tests Azure: `http://169.254.169.254/metadata/instance`
- If accessible → Can steal credentials, API keys

**2. Protocol Handler Abuse**
- Tests `file:///etc/passwd` → Read local files
- Tests `dict://`, `gopher://`, `ftp://` → Internal service access

**3. Internal Network Access**
- Tests `localhost`, `127.0.0.1`, `0.0.0.0`
- Tests internal services on common ports (SSH:22, MySQL:3306, Redis:6379)

**4. IP Representation Bypasses**
- Decimal: `http://2130706433/` (= 127.0.0.1)
- Hexadecimal: `http://0x7f.0x0.0x0.0x1/`
- Octal: `http://0177.0.0.1/`

**5. Blind SSRF (Timing-Based)**
- Requests internal IP that should timeout
- Measures response time
- Significant delay → Server tried to connect

#### Parameter Detection
Looks for parameter names like:
- `url`, `uri`, `link`, `redirect`, `target`
- `fetch`, `proxy`, `callback`, `host`

---

## 6. Command Injection Agent

### What It Does
Detects OS command injection where attackers can execute system commands.

### How It Works

#### Detection Techniques

**1. Error-Based Detection**
- Injects separators like `; whoami`, `| id`, `&& uname -a`
- Checks response for command output:
  - `uid=` → Linux `id` command output
  - `Linux` → `uname` output
  - `root:` → `/etc/passwd` file content

**2. Time-Based Blind Detection**
- Injects `; sleep 5` (Unix) or `& ping -n 5 127.0.0.1` (Windows)
- **Statistical Analysis**:
  - Measures baseline response time (3 samples)
  - Tests with multiple delay values (3s, 5s, 7s)
  - Requires 2+ confirmations to reduce false positives

#### OS Detection
- Detects Windows via technology stack (IIS, ASP.NET, .aspx)
- Uses platform-specific payloads:
  - **Unix**: `sleep`, `cat`, `whoami`
  - **Windows**: `timeout`, `ping`, `dir`

#### Parameter Prioritization
Scores parameters by name:
- High score: `cmd`, `exec`, `ping`, `host`
- Medium score: `file`, `path`, `query`
- Also scores by URL patterns: `/ping`, `/exec`, `/diagnostic`

---

## 7. API Security Agent

### What It Does
Comprehensive API testing based on OWASP API Security Top 10 2023.

### How It Works

#### What It Tests

**1. BOLA/IDOR (API1:2023)**
- Detects Broken Object Level Authorization
- Tests numeric IDs: Changes `/api/users/5` → `/api/users/6`
- Tests UUIDs: Manipulates UUID last character
- If both accessible with different data → Vulnerable

**2. Excessive Data Exposure (API3:2023 - Part 1)**
- Scans API responses for sensitive data
- Detects:
  - Passwords, secrets, API keys
  - SSNs, credit card numbers
  - Email addresses, tokens

**3. Mass Assignment (API3:2023 - Part 2)**
- Injects privileged fields: `{"is_admin": true, "role": "admin"}`
- Checks if fields are accepted/echoed back
- Enables privilege escalation

**4. Rate Limiting (API4:2023)**
- Sends 50 rapid requests in ~10 seconds
- If >90% succeed → Missing rate limiting

** 5. Broken Function Level Authorization (API5:2023)**
- Tests admin endpoints without authentication
- Paths like `/admin`, `/api/admin`, `/api/config`
- If accessible → BFLA vulnerability

**6. Security Misconfigurations (API8:2023)**
- Missing security headers (X-Content-Type-Options, X-Frame-Options, CSP)
- Exposed config files (`.env`, `config.json`, `swagger.json`)
- Weak CORS policies
- Insecure cookies (missing HttpOnly, Secure, SameSite)

**7. Old API Versions (API9:2023)**
- Discovers multiple API versions (/api/v1, /v2, /v3)
- Old versions may have unpatched vulnerabilities

---

## 8. GitHub Agent

### What It Does
Analyzes GitHub repository source code for security issues.

### How It Works

#### Scanning Workflow

**1. Repository Discovery**
- Detects default branch (main/master)
- Fetches recursive file list

**2. AI Hotspot Detection**
- Uses AI to identify high-risk files
- Looks for authentication, API, config, admin code
- Prioritizes based on file names and paths

**3. File Prioritization**
Priority scoring:
- **Critical (100)**: `.env` files, `secrets.json`
- **High (80)**: Auth/API files, login handlers
- **Medium (60)**: Database connections
- **Low (40)**: Regular source code
- **Minimal (20)**: Test files (ignored for vulnerabilities)

**4. Secret Detection**
Scans for:
- **AWS**: `AKIA[0-9A-Z]{16}`
- **GitHub**: `ghp_[a-zA-Z0-9]{36}`
- **OpenAI**: `sk-[a-zA-Z0-9]{48}`
- **Stripe**: `sk_live_[0-9a-zA-Z]{24,}`
- **Database Connections**: `postgres://user:pass@host:port/db`

Validates secrets with:
- **Entropy calculation**: Minimum 4.5 bits
- **Length checks**: 20-200 characters
- **Pattern matching**: High-confidence patterns

**5. Vulnerability Pattern Detection**
- **SQL Injection**: Detects string concatenation in SQL queries
- **XSS**: Detects unsafe HTML rendering
- **Path Traversal**: Detects file operations with user input

**6. Dependency Scanning**
- Parses `package.json`, `requirements.txt`, `pom.xml`, etc.
- Queries OSV database for known vulnerabilities
- Reports CVEs with severity and description

#### False Positive Reduction
**Ignores:**
- Test files (`test_*.py`, `*.test.js`, `/tests/`)
- Payload definitions (`/payloads/`, `*_payloads.py`)
- Scanner infrastructure (`/agents/`, `/scanner/`)
- Documentation (`/docs/`, `/examples/`)

**Only flags:**
- Production code (`/api/`, `/routes/`, `/controllers/`, `/src/`)
- High confidence findings (≥70%)

---

## 9. Orchestrator

### What It Does
Coordinates all agents and manages the scan workflow.

### How It Works

#### Scan Phases

**1. Reconnaissance** (Progress: 5-15%)
- Discovers endpoints
- Detects technology stack

**2. Active Scanning** (Progress: 15-85%)
- Runs agents in dependency order:
  1. GitHub Agent (if GitHub URL)
  2. Auth Agent + API Agent (discover endpoints)
  3. SQL, XSS, CSRF, SSRF, Command Injection (exploit endpoints)

**3. Analysis** (Progress: 85-92%)
- Validates evidence
- Filters false positives
- Correlates findings across agents
- Applies exploitability gates
- Deduplicates results

**4. Reporting** (Progress: 92-100%)
- Calculates metrics
- Sorts by severity
- Generates final report

#### Intelligence Layer

**Exploitability Gates**
Downgrades severity if:
- Authentication required + no credentials found
- WAF detected + bypass not confirmed
- Network isolation detected

**Evidence Validation**
Checks for:
- Actual command output vs error messages
- Real SQL errors vs generic errors
- Unique responses vs cached responses

**Correlation**
- Groups related findings
- Boosts confidence for confirmed attack chains
- Example: SQL injection + exposed DB credentials = CRITICAL

---

## Summary Table

| Agent | Purpose | Speed | Requires URL Parameters |
|-------|---------|-------|------------------------|
| **SQL Injection** | Database query manipulation | Medium | ❌ No - auto-discovers |
| **XSS** | JavaScript injection | Fast | ❌ No - tests all params |
| **Authentication** | Login bypass, session issues | Medium | ❌ No - finds login pages |
| **CSRF** | Cross-site request forgery | Fast | ❌ No - tests state-changing endpoints |
| **SSRF** | Internal resource access | Medium | ⚠️ Looks for URL-like params |
| **Command Injection** | OS command execution | Slow | ⚠️ Looks for command-like params |
| **API Security** | API misconfigurations | Fast | ❌ No - discovers API endpoints |
| **GitHub** | Source code analysis | Slow | ✅ Yes - requires GitHub URL |

---

## Key Takeaways

1. **No Specific URLs Required**: Most agents work with any URL and automatically discover endpoints/parameters
2. **Smart Prioritization**: Agents focus on high-risk areas first (login pages, API endpoints, cloud metadata)
3. **Multiple Techniques**: Each agent uses multiple detection methods (error-based, time-based, blind, etc.)
4. **False Positive Reduction**: Intelligence layer validates findings and filters test code/payloads
5. **Dependency Awareness**: Agents work together - some discover endpoints for others to exploit

---

## Questions?

For specific implementation details, check the agent source code in `backend/agents/`:
- `sql_injection_agent.py`
- `xss_agent.py`
- `auth_agent.py`
- `csrf_agent.py`
- `ssrf_agent.py`
- `command_injection_agent.py`
- `api_security_agent.py`
- `github_agent.py`
- `orchestrator.py`
