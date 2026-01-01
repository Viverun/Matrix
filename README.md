# Matrix - AI-Powered Autonomous Security Scanner

<div align="center">

![Matrix](https://img.shields.io/badge/Matrix-Autonomous%20Security-red?style=for-the-badge&logo=matrix&logoColor=white)
![Python](https://img.shields.io/badge/Python-3.11+-blue?style=for-the-badge&logo=python)
![FastAPI](https://img.shields.io/badge/FastAPI-0.109+-green?style=for-the-badge&logo=fastapi)
![Next.js](https://img.shields.io/badge/Next.js-14-black?style=for-the-badge&logo=next.js)
![Redis](https://img.shields.io/badge/Redis-Queue-red?style=for-the-badge&logo=redis)

### 🤖 8 Specialized AI Agents • 🎯 OWASP Top 10 Coverage • 📊 CISO-Grade Reports

</div>

---

## 🚀 Overview

**Matrix** is an AI-powered autonomous security testing platform built with a mission to democratize penetration testing. Designed to rival enterprise-grade solutions, Matrix leverages **Groq AI** (Llama 3.3 70B) and intelligent agent orchestration to simulate real-world attacker behavior and discover vulnerabilities before they're exploited.

### Why Matrix?

- **🧠 Intelligent Orchestration**: 8 specialized AI agents work in concert, sharing intelligence through a unified scan context
- **⚡ Real-Time Visualization**: Watch agents analyze your application with live terminal logs and animated status cards
- **📈 Professional Reporting**: Export CISO-grade security reports with CVSS v3.1 scoring, CWE mappings, and severity distributions
- **🎨 Premium UI/UX**: Beautiful glassmorphism design with Matrix rain animations and responsive layouts
- **🔬 Built for Scale**: Async task processing with Redis Queue (RQ), WAF evasion, rate limiting, and request caching

---

## ✨ Features

### 🤖 8 Specialized Security Agents

Each agent is purpose-built for specific attack vectors, powered by AI analysis and exploitability gates:

| Agent | Attack Vectors | Detection Methods | Example Findings |
|-------|---------------|-------------------|------------------|
| **SQL Injection** | Error-based, Blind, Time-based | AI-powered pattern matching, Database error analysis | Union-based extraction, Boolean blind SQLi |
| **Cross-Site Scripting (XSS)** | Reflected, Stored, DOM-based | Payload reflection detection, Context analysis | Script injection, Event handler XSS |
| **CSRF** | Token bypass, SameSite analysis | Form submission analysis, Cookie inspection | Missing CSRF tokens, Weak SameSite policies |
| **SSRF** | Internal IP access, Cloud metadata | URL parameter testing, Response analysis | AWS metadata access, Internal network probing |
| **Command Injection** | OS command execution, Path traversal | Shell metacharacter testing, Output analysis | Remote code execution, File system access |
| **Authentication** | Brute force, Session hijacking | Login flow analysis, Session token testing | Weak passwords, Session fixation |
| **API Security** | IDOR, Mass assignment, Rate limiting | Endpoint enumeration, Parameter fuzzing | Broken object-level authorization, Data exposure |
| **GitHub Security** | Secret scanning, Dependency analysis | Repository analysis, Code pattern matching | Hardcoded credentials, Vulnerable dependencies |

### 🎯 Advanced Capabilities

- **🔥 WAF Evasion**: Optional adversarial techniques with explicit user consent
- **📊 Confidence Scoring**: Hierarchical scoring based on detection method, evidence quality, and environmental factors
- **🔗 Evidence Correlation**: Cross-agent intelligence sharing to reduce false positives
- **⚙️ Exploitability Gates**: Automated validation to downgrade non-exploitable findings
- **📈 Scan Metrics**: Evidence completeness, chained findings ratio, signal quality scores
- **🎯 Real-World Validation**: Tested against OWASP intentionally vulnerable applications

### 🎨 Professional UI/UX

- **Modern Design**: Glassmorphism cards, warm color palette, typography excellence
- **Matrix Rain Animation**: Dynamic background with custom React component
- **Real-Time Progress**: Live agent status cards with animated transitions
- **Professional Reports**: Table-based findings with CVSS vectors, bordered severity badges
- **Export Options**: PDF reports with charts, JSON exports for CI/CD integration
- **Responsive Layout**: Mobile-first design that works beautifully on all devices

---

## 🏗️ Architecture

Matrix employs a sophisticated **multi-agent orchestration** architecture with four distinct phases:

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                          🎯 MATRIX ORCHESTRATOR                               │
│                                                                               │
│  • Dependency Resolution Engine    • Scan Context (Shared State)             │
│  • Progress Tracking & Callbacks   • Error Handling & Retry Logic            │
│  • Result Aggregation & Metrics    • Agent Lifecycle Management              │
└───────────────────────────────────┬──────────────────────────────────────────┘
                                    │
                    ┌───────────────┼───────────────┐
                    ▼               ▼               ▼
         ┌──────────────┐  ┌──────────────┐  ┌──────────────┐
         │  PHASE 1:    │  │  PHASE 2:    │  │  PHASE 3:    │
         │RECONNAISSANCE│─▶│  DISCOVERY   │─▶│EXPLOITATION  │
         └──────────────┘  └──────────────┘  └──────────────┘
                │                  │                  │
                │                  │                  │
        ┌───────┴────────┐  ┌──────┴──────┐  ┌───────┴─────────┐
        │                │  │             │  │                 │
    ┌───▼────┐     ┌─────▼──┐  ┌─────▼─────┐  ┌─────▼─────┐ ┌──▼──────┐
    │ GitHub │     │ Target │  │   Auth    │  │   SQLi    │ │   XSS   │
    │ Scanner│     │ Enumera│  │   Agent   │  │   Agent   │ │  Agent  │
    │        │     │  tion  │  │           │  │           │ │         │
    │• Secret│     │• Crawl │  │• Login    │  │• Error-   │ │• Reflect│
    │  Scan  │     │• Spider│  │• Session  │  │  based    │ │• Stored │
    │• Vulns │     │• EndPts│  │• Cookies  │  │• Blind    │ │• DOM    │
    │• Deps  │     │• Forms │  │• JWT Test │  │• Time     │ │• Context│
    └────────┘     └────────┘  └───────────┘  └───────────┘ └─────────┘
                                       │              │           │
                                ┌──────┴──────┐  ┌────┴─────┐ ┌──┴──────┐
                                │   API Sec   │  │  CSRF    │ │  SSRF   │
                                │    Agent    │  │  Agent   │ │  Agent  │
                                │             │  │          │ │         │
                                │• IDOR       │  │• Token   │ │• Cloud  │
                                │• Rate Limit │  │• SameSite│ │  Meta   │
                                │• CORS       │  │• CSRF    │ │• Intern │
                                └─────────────┘  └──────────┘ └─────────┘
                                       │              │           │
                                       │      ┌───────┴───────┐   │
                                       │      │   Cmd Inject  │   │
                                       │      │     Agent     │   │
                                       │      │               │   │
                                       │      │• OS Commands  │   │
                                       │      │• Path Trav    │   │
                                       │      │• Shell Meta   │   │
                                       │      └───────────────┘   │
                                       └──────────┬───────────────┘
                                                  │
                                    ┌─────────────▼─────────────┐
                                    │      PHASE 4:             │
                                    │  INTELLIGENCE LAYER       │
                                    │                           │
                                    │  🧠 AI Analysis (Groq)    │
                                    │  🔗 Evidence Correlation  │
                                    │  ⚖️  Confidence Scoring   │
                                    │  🚫 False Positive Filter │
                                    │  🎯 Exploitability Gates  │
                                    │  📊 Deduplication Engine  │
                                    └───────────┬───────────────┘
                                                │
                                    ┌───────────▼───────────────┐
                                    │   📤 OUTPUT LAYER         │
                                    │                           │
                                    │  • Vulnerability DB       │
                                    │  • PDF Report Generator   │
                                    │  • JSON Export            │
                                    │  • Real-time WebSocket    │
                                    │  • Scan Metrics           │
                                    └───────────────────────────┘

                            ┌─────────────────────────────┐
                            │  INFRASTRUCTURE LAYER       │
                            │                             │
                            │  Redis Queue (RQ Worker)    │
                            │  SQLite/PostgreSQL          │
                            │  FastAPI Backend            │
                            │  Next.js Frontend           │
                            └─────────────────────────────┘
```

### Technology Stack

**Frontend:**
- Next.js 14 (React, TypeScript)
- TailwindCSS with custom design system
- Recharts for data visualization
- Lucide React icons
- Custom animations (Matrix rain, fade-ins)

**Backend:**
- FastAPI (Python 3.11+)
- SQLAlchemy ORM with SQLite/PostgreSQL
- Groq AI (Llama 3.3 70B)
- Redis Queue (RQ) for async task processing
- httpx/aiohttp for concurrent HTTP requests
- BeautifulSoup4 for HTML parsing

**Infrastructure:**
- Redis for task queue and caching
- SQLite (dev) / PostgreSQL (prod)
- Docker Compose for containerization

---

## 🛠️ Quick Start

### Prerequisites

- **Python 3.11+**
- **Node.js 18+**
- **Redis** (for async scanning)
- **Groq API Key** ([Get one free](https://console.groq.com))

### Backend Setup

```bash
cd backend

# Create virtual environment
python -m venv venv
venv\Scripts\activate  # Windows
# source venv/bin/activate  # Linux/Mac

# Install dependencies
pip install -r requirements.txt

# Configure environment
copy .env.example .env
# Edit .env and add:
# GROQ_API_KEY=your_groq_api_key_here
# GITHUB_TOKEN=your_github_token (optional, for GitHub scans)

# Start Redis (required for async scans)
# Windows: Download from https://github.com/microsoftarchive/redis/releases
# Linux/Mac: sudo service redis-server start

# Run the backend API
uvicorn main:app --port 8000 --reload

# In a new terminal, start the RQ worker
python rq_worker.py
```

### Frontend Setup

```bash
cd frontend

# Install dependencies
npm install

# Run development server
npm run dev
```

### Access the Application

- **Frontend**: http://localhost:3000
- **Backend API**: http://localhost:8000
- **API Docs (Swagger)**: http://localhost:8000/docs
- **Interactive API**: http://localhost:8000/redoc

---

## 📖 Usage

### Web Interface

1. **Navigate** to http://localhost:3000
2. **Sign up** or log in to create an account
3. **Go to Hub** → Click "Launch Security Scanner"
4. **Enter target URL** (e.g., `https://example.com`)
5. **Watch agents work** in real-time with live logs
6. **Review findings** in the professional security report
7. **Export** as PDF or JSON for documentation

### API Usage

#### Create a Scan

```bash
curl -X POST http://localhost:8000/api/scans/ \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "target_url": "https://example.com",
    "scan_type": "FULL",
    "enable_waf_evasion": false
  }'
```

#### Check Scan Status

```bash
curl http://localhost:8000/api/scans/1 \
  -H "Authorization: Bearer YOUR_JWT_TOKEN"
```

#### Get Vulnerabilities

```bash
curl http://localhost:8000/api/scans/1/vulnerabilities \
  -H "Authorization: Bearer YOUR_JWT_TOKEN"
```

#### Export Reports

```bash
# PDF Report
curl http://localhost:8000/api/scans/1/report/pdf \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  --output security_report.pdf

# JSON Export
curl http://localhost:8000/api/scans/1/report/json \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  --output security_report.json
```

---

## 📊 Evaluation & Benchmarks

Matrix's detection capabilities are validated against intentionally vulnerable applications:

- **OWASP Juice Shop**: E-commerce web application
- **DVWA**: Damn Vulnerable Web Application
- **Acunetix VulnWeb**: SQL injection and XSS testbed

Performance metrics (agent-specific confidence scores and detection rates) are continuously tracked. Run the evaluation suite:

```bash
cd backend
python evaluate_scanner.py
cat benchmark_results.json
```

See the [Documentation](http://localhost:3000/docs) page for ROC curves, precision/recall metrics, and validation methodology.

---

## 🎯 Roadmap

### ✅ Completed

- [x] Core agent orchestration with dependency graph
- [x] All 8 security agents (SQLi, XSS, CSRF, SSRF, Cmd Injection, Auth, API, GitHub)
- [x] Real-time scan progress with live terminal logs
- [x] Professional security report UI with CVSS scoring
- [x] PDF/JSON export functionality
- [x] WAF evasion with consent mechanism
- [x] Confidence scoring and exploitability gates
- [x] Evidence correlation and deduplication
- [x] Next.js 14 frontend with premium UI/UX

### 🚧 In Progress

- [ ] Enhanced GitHub agent with CVE correlation
- [ ] Vulnerability remediation code snippets
- [ ] Multi-language support (Python, JavaScript, PHP)

### 📋 Planned

- [ ] **CI/CD Integration**: GitHub Actions, GitLab CI plugins
- [ ] **Scheduled Scans**: Cron-based recurring scans
- [ ] **Multi-Target Campaigns**: Scan multiple URLs in one job
- [ ] **Webhook Notifications**: Slack, Discord, email alerts
- [ ] **Custom Agent SDK**: Build your own security agents
- [ ] **Compliance Reports**: OWASP ASVS, PCI-DSS mapping

---

## 📚 Documentation

- **[Actionable Findings Guide](ACTIONABLE_FINDINGS.md)** - Structured reporting, evidence tracking, diff detection
- **[Quick Reference](QUICK_REFERENCE.md)** - API usage and code examples
- **[Architecture Documentation](http://localhost:3000/docs)** - Agentic workflow, evaluation metrics

---

## 🔒 Security & Ethics

### Responsible Use

> **⚠️ IMPORTANT**: This tool is for **authorized security testing only**. Always obtain proper written permission before scanning any target. Unauthorized scanning is illegal and unethical.

### WAF Evasion Disclaimer

WAF evasion techniques are **disabled by default** and require explicit user consent via a warning modal. These features are intended solely for:

- Authorized penetration testing
- Security research with permission
- Red team exercises in controlled environments

Misuse of these capabilities may violate computer fraud laws (CFAA, GDPR, etc.). Users are solely responsible for compliance with applicable laws.

---

## 🤝 Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-agent`)
3. Commit your changes (`git commit -m 'Add amazing agent'`)
4. Push to the branch (`git push origin feature/amazing-agent`)
5. Open a Pull Request

---

## 📜 License

Matrix is licensed under **PolyForm Noncommercial 1.0.0**

### ✅ FREE for Everyone:

Matrix is **completely FREE** for:

- 🏢 **Companies** - Test and secure YOUR OWN applications internally
- 🎓 **Education** - Universities, training programs, security courses
- 🔬 **Research** - Academic research, security research, bug bounties
- 👥 **Security Teams** - Internal pentesting, red/blue teams, SOC operations
- 💚 **Non-Profits** - Charities, NGOs, government institutions
- 🏠 **Personal Use** - Individual learning, hobby projects, portfolio building

**Example Valid Uses:**
- ✅ Netflix uses Matrix to scan their own APIs
- ✅ University teaches web security using Matrix in labs
- ✅ Security researcher finds vulnerabilities with Matrix
- ✅ Startup scans their SaaS product before launch
- ✅ Pentester uses Matrix during internal company assessment

### 💰 Commercial License Required for:

You need a **paid commercial license** if you:

- ❌ **Sell scanning services** - Offer Matrix-as-a-Service to customers
- ❌ **Charge for Matrix scans** - Consulting firms billing clients for Matrix usage
- ❌ **Resell Matrix** - Bundle Matrix in paid security products
- ❌ **Create competing products** - Build commercial derivatives of Matrix

**Example Invalid Uses Without License:**
- ❌ "SecureCloud.io" offers hosted Matrix scanning ($99/month)
- ❌ Consulting firm charges clients $5,000 for Matrix security assessment
- ❌ MSSP includes Matrix in managed security service
- ❌ Company forks Matrix and sells "Enterprise Scanner Pro"

### 🤔 Not Sure If You Need a License?

**If you're using Matrix to secure YOUR OWN products/services → FREE ✅**  
**If you're charging OTHERS for Matrix scans/services → Need License ❌**

Questions? Email: licensing@matrix-scanner.com

---

**Full License:** [LICENSE](./LICENSE)  
**Commercial Licensing:** [COMMERCIAL-LICENSE.md](./COMMERCIAL-LICENSE.md)  
**FAQ:** [LICENSE-FAQ.md](./LICENSE-FAQ.md)

[![License: PolyForm Noncommercial](https://img.shields.io/badge/License-PolyForm_Noncommercial-blue.svg)](https://polyformproject.org/licenses/noncommercial/1.0.0/)

---

## 🙏 Acknowledgments

- **Groq** for blazing-fast AI inference
- **OWASP** for vulnerability classification standards
- **Google Gemini** for initial AI prototyping
- The security community for continuous feedback

---

<div align="center">
  <strong>Built with ❤️ for the security community</strong>
  <br><br>
  <sub>Matrix © 2025 • AI-Powered Security • OWASP Top 10 Coverage</sub>
</div>
