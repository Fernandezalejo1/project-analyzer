# 🔍 Project Analyzer — AI-Powered Software Auditor

An intelligent project analysis tool that performs a complete audit of your software project: architecture, security, vulnerabilities, code quality, dependencies, performance, and more.

## ✨ Features

| Module | Description |
|--------|-------------|
| 📐 Architecture | Detects languages, frameworks, project type, generates architecture map |
| 📦 Dependencies | Scans package.json, requirements.txt, Cargo.toml, pom.xml, go.mod, etc. |
| 🔐 Security | Detects leaked secrets, API keys, credentials, .env files, certificates |
| 🛡️ Vulnerabilities | SQL Injection, XSS, CSRF, Command Injection, Path Traversal, SSRF, etc. |
| 📊 Code Quality | Cyclomatic complexity, duplication, dead code, maintainability, technical debt |
| 📈 Git History | Large commits, secrets in history, abandoned branches, contributor stats |
| ⚡ Performance | N+1 queries, blocking I/O, expensive loops, memory issues, heavy files |
| 🤖 AI Analysis | Architecture recommendations, scalability concerns, priority actions |
| 📝 Documentation | Auto-generates README, architecture diagrams (Mermaid), onboarding guide |
| 📋 Executive Report | 0-100 score with category breakdown and prioritized action items |

## 🚀 Quick Start

### Prerequisites

- Python 3.11+
- Git (for git history analysis and cloning repos)

### Backend Setup

```bash
cd backend
pip install -r requirements.txt
```

### Running the CLI

```bash
# Analyze a local project
python -m app.main /path/to/your/project

# Analyze a GitHub repo (clones it automatically)
python -m app.main https://github.com/user/repo

# The CLI generates two reports:
#   analysis-report.json  (full data)
#   analysis-report.md    (human-readable markdown)
```

### Running the Web UI

**Terminal 1 — API Server:**
```bash
cd backend
python -m app.main serve
# API runs at http://localhost:8000
# Swagger docs at http://localhost:8000/docs
```

**Terminal 2 — Frontend:**
```bash
# Simply open frontend/index.html in your browser
# No build tools needed!

# Or serve it:
cd frontend
python -m http.server 5173
# Open http://localhost:5173
```

## 📖 Architecture

```
project-analyzer/
├── backend/
│   ├── app/
│   │   ├── analyzer.py              # Main orchestrator
│   │   ├── main.py                  # FastAPI app + CLI entry
│   │   ├── api/routes.py            # API endpoints
│   │   ├── analyzers/
│   │   │   ├── architecture.py      # Language/framework detection
│   │   │   ├── dependencies.py      # Dependency scanning
│   │   │   ├── security.py          # Secret/credential detection
│   │   │   ├── vulnerabilities.py   # Vulnerability patterns
│   │   │   ├── code_quality.py      # Complexity, duplication metrics
│   │   │   ├── git_analyzer.py      # Git history analysis
│   │   │   ├── performance.py       # Performance anti-patterns
│   │   │   ├── ai_analysis.py       # AI recommendations engine
│   │   │   ├── documentation.py     # Auto-doc generation
│   │   │   └── executive_report.py  # Scoring & priority system
│   │   └── models/schemas.py        # Pydantic data models
│   └── requirements.txt
├── frontend/
│   ├── index.html                   # Dashboard UI
│   ├── style.css                    # Dark-theme styles
│   └── app.js                       # Frontend logic
└── README.md
```

## 🎯 Scoring System

The executive report scores each category on a 0-10 scale:

| Score | Rating |
|-------|--------|
| 90-100 | 🟢 EXCELLENT |
| 75-89 | 🔵 GOOD |
| 60-74 | 🟡 FAIR |
| 40-59 | 🟠 POOR |
| 0-39 | 🔴 CRITICAL |

## 🔧 Supported Languages

Python, JavaScript, TypeScript, Java, Go, Rust, C#, C++, Ruby, PHP, Swift, Kotlin, Dart

## 📦 Supported Dependency Files

package.json, requirements.txt, Pipfile, pyproject.toml, Cargo.toml, pom.xml, build.gradle, go.mod, Gemfile, composer.json, pubspec.yaml, *.csproj

## 🛡️ Security Patterns Detected

- API Keys (OpenAI, Anthropic, Stripe, Slack, etc.)
- AWS/GCP/Azure credentials
- GitHub tokens
- Bearer tokens & JWTs
- Database connection strings
- Passwords & private keys
- Firebase configuration

## 📊 License

MIT
