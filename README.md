# Matrix - Agent-Driven Cyber Threat Simulator

<div align="center">
  <img src="https://img.shields.io/badge/Python-3.11+-blue?style=for-the-badge&logo=python" alt="Python">
  <img src="https://img.shields.io/badge/FastAPI-0.109+-green?style=for-the-badge&logo=fastapi" alt="FastAPI">
  <img src="https://img.shields.io/badge/Next.js-14+-black?style=for-the-badge&logo=next.js" alt="Next.js">
  <img src="https://img.shields.io/badge/Gemini-AI-purple?style=for-the-badge&logo=google" alt="Gemini AI">
</div>

## 🚀 Overview

Matrix is an AI-powered autonomous security testing platform that democratizes penetration testing. Using Google Gemini and intelligent agents, it automatically simulates cyber attacks, identifies vulnerabilities, and provides actionable remediation guidance.

## ✨ Features

- 🤖 **AI-Powered Analysis** - Groq AI (Llama 3.3 70B) for intelligent vulnerability detection
- 🔍 **8 Security Agents** - SQL Injection, XSS, CSRF, SSRF, Command Injection, Auth, API Security, GitHub
- 📊 **Actionable Findings** - CVSS v3.1 scoring, evidence chains, diff-based detection
- 📝 **Multi-Format Reports** - JSON/HTML/Markdown with PoC payloads and remediation code
- 🎯 **Production-Grade** - WAF evasion, rate limiting, request caching, statistical analysis
- 🔌 **REST API** - Programmatic access for CI/CD integration

## 📖 Documentation

- **[Actionable Findings Guide](ACTIONABLE_FINDINGS.md)** - Structured reporting, evidence tracking, diff detection
- **[Quick Reference](QUICK_REFERENCE.md)** - API usage and code examples
- **Security Refinements** - Agent performance, correlation engine, exploitability gates

## 🏗️ Architecture

```
Matrix/
├── backend/                 # FastAPI Python backend
│   ├── agents/             # Security testing agents
│   │   ├── orchestrator.py
│   │   ├── sql_injection_agent.py
│   │   ├── xss_agent.py
│   │   ├── auth_agent.py
│   │   └── api_security_agent.py
│   ├── api/                # REST API routes
│   ├── core/               # Core utilities
│   ├── models/             # Database models
│   ├── scanner/            # Target analysis
│   └── services/           # Business logic
│
└── frontend/               # Next.js React frontend
    ├── app/                # App router pages
    ├── components/         # UI components
    └── lib/                # Utilities
```

## 🛠️ Quick Start

### Prerequisites

- Python 3.11+
- Node.js 18+
- Google Gemini API key

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
# Edit .env and add your GOOGLE_API_KEY

# Run the server
uvicorn main:app --reload
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
- **API Docs**: http://localhost:8000/docs

## 🔒 Security Agents

| Agent | Description | Vulnerabilities Detected |
|-------|-------------|-------------------------|
| SQL Injection | Tests database queries | Error-based, Blind, Time-based SQLi |
| XSS | Cross-site scripting | Reflected, Stored, DOM-based XSS |
| Authentication | Login security | Brute force, Session issues, Default creds |
| API Security | REST API testing | IDOR, Data exposure, CORS issues |

## 📖 API Usage

### Create a Scan

```bash
curl -X POST http://localhost:8000/api/scans/ \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"target_url": "https://example.com"}'
```

### Get Scan Results

```bash
curl http://localhost:8000/api/scans/1 \
  -H "Authorization: Bearer YOUR_TOKEN"
```

## 🎯 Roadmap

- [x] Core backend infrastructure
- [x] SQL Injection Agent
- [x] XSS Agent
- [x] Authentication Agent
- [x] API Security Agent
- [x] Target Analyzer
- [x] Frontend Dashboard
- [ ] CSRF Agent
- [ ] File Upload Agent
- [ ] Report Generation (PDF)
- [ ] CI/CD Integration
- [ ] Scheduled Scans

## ⚠️ Disclaimer

This tool is for **authorized security testing only**. Always obtain proper permission before scanning any target. Unauthorized scanning is illegal and unethical.

## 📄 License

MIT License - See LICENSE for details.

---

<div align="center">
  <strong>Built with ❤️ for the security community</strong>
</div>
