# 🎯 BountyLedger

**An agentic bug bounty hunting pipeline & research ledger.**

BountyLedger is a Python CLI tool that automates the full lifecycle of bug bounty research — from HackerOne scope fetching and subdomain enumeration to SSRF canary deployment and callback monitoring. It keeps a structured SQLite ledger of every sink, test, and hit so nothing falls through the cracks.

---

## ✨ Features

- **Autonomous Hunting** — End-to-end pipeline: scope → recon → harvest → deploy → monitor
- **HackerOne Integration** — Fetch program scopes and search for bounty programs via the API
- **Recon Engine** — Subdomain enumeration (`subfinder`), live host probing (`httpx`), and web crawling (`katana`)
- **Parameter Harvesting** — Scan raw HTTP requests, source code, and HAR files to identify potential SSRF sinks
- **Canary Deployment** — Generate unique callback URLs tied to specific sinks
- **Callback Server** — Self-hosted HTTP listener with ngrok tunneling + Interactsh fallback for OAST detection
- **Safety Guardrails** — Blocks internal IPs, private ranges, localhost, cloud metadata endpoints, and dangerous schemes
- **Meta Bug Bounty Support** — First-class integration for Meta's SSRF canary token system
- **SQLite Ledger** — Persistent tracking of sinks, tests, and hits with full audit history
- **Rich CLI** — Beautiful terminal output powered by Typer and Rich

---

## 🚀 Quick Start

### Prerequisites

- **Python 3.10+**
- **Go** (for ProjectDiscovery tools)
- **ngrok** (optional, for public callback tunneling)

### Installation

```bash
# Clone the repo
git clone <repo-url> && cd "Bug Hunter"

# Run the automated setup (installs Go tools + Python package)
bash setup.sh
```

The setup script installs:

| Tool | Purpose |
|------|---------|
| `subfinder` | Subdomain enumeration |
| `httpx` | HTTP probing |
| `katana` | Web crawling & URL discovery |
| `nuclei` | Vulnerability scanning |
| `interactsh-client` | OAST callback server |

### Configuration

```bash
# Interactive setup wizard
bounty setup
```

Or edit `config.json` directly:

```json
{
  "listener_domain": "auto",
  "allowed_scope": [],
  "hackerone_username": "your_username",
  "hackerone_api_token": "your_api_token",
  "rate_limit": 10,
  "max_subdomains": 500,
  "crawl_depth": 3,
  "auto_report": true
}
```

---

## 📖 Usage

### Full Autonomous Hunt

```bash
# Launch a hunt against a HackerOne program
bounty hunt paypal --monitor 600

# Dry-run (no actual requests)
bounty hunt shopify --dry-run
```

### Reconnaissance

```bash
# Full recon pipeline on a domain
bounty recon paypal.com --depth 3 --rate 10

# View HackerOne program scope
bounty scope paypal
```

### Sink Management

```bash
# Scan text or files for potential sinks
bounty scan "GET /api/proxy?url=http://example.com"
bounty scan ./traffic.har

# Manually add a sink
bounty add-sink --surface "Image Proxy" --param "url" --risk High

# List all tracked sinks
bounty list-sinks
```

### Testing & Canary Deployment

```bash
# Generate a test canary for a sink
bounty gen-test 1

# Log a Meta SSRF canary test
bounty meta-test 1 "https://canary-token-url.fbsbx.com/..."

# Check Meta canary status
bounty meta-check
```

### Callback Monitoring

```bash
# Start self-hosted callback server (default)
bounty monitor --duration 600 --port 8888

# Use Interactsh instead
bounty monitor --interactsh --duration 300
```

### Results & Reporting

```bash
# Mark a test as HIT
bounty mark-hit 3 --notes "Confirmed blind SSRF"

# Generate a markdown report
bounty report 3 --output ./report.md

# View stats
bounty stats

# List all tests (filter by status)
bounty list-tests --status HIT
```

### Utilities

```bash
# Generate a redirect bypass script
bounty gen-redirect-script http://internal.target --lang python

# Show current config
bounty config
```

---

## 🏗️ Architecture

```
Bug Hunter/
├── bounty_ledger/           # Core package
│   ├── cli.py               # Typer CLI — all commands
│   ├── database.py          # SQLite schema + CRUD (sinks, tests)
│   ├── guardrails.py        # URL safety validation & scope checking
│   ├── harvester.py         # Parameter scanning (text, HAR, HTTP)
│   ├── hunter.py            # Autonomous hunt orchestrator
│   ├── recon.py             # Recon engine (subfinder → httpx → katana)
│   ├── callback_server.py   # Self-hosted HTTP callback listener
│   ├── interactsh.py        # Interactsh OAST integration
│   └── hackerone.py         # HackerOne API v1 client
├── tests/                   # Test suite
│   ├── test_guardrails.py   # Safety validation tests
│   └── test_harvester.py    # Parameter scanning tests
├── recon_output/            # Saved recon results (JSON)
├── config.json              # Runtime configuration
├── pyproject.toml           # Package metadata
├── setup.sh                 # One-command environment setup
└── requirements.txt         # Python dependencies
```

### Pipeline Flow

```
HackerOne Scope → Subdomain Enum → Live Host Probing → URL Crawling
        ↓                                                    ↓
   Scope Filter                                    Parameter Harvesting
        ↓                                                    ↓
   Guardrails ←←←←←←←←←←←←←←←←←←←←←←←←←←←←← Sink Detection
        ↓                                                    ↓
   Safety Check                                   Canary Deployment
        ↓                                                    ↓
   Block Internal ──→ (rejected)           Callback Monitoring
        ↓                                                    ↓
   Allow External ──→ Test Logged              Hit Confirmed → Report
```

---

## 🛡️ Safety

BountyLedger has **server-side guardrails** that prevent targeting:

- Private/internal IPs (`127.x`, `10.x`, `192.168.x`, `172.16-31.x`)
- IPv6 loopback and private ranges (`::1`, `fc00::`, `fe80::`)
- Cloud metadata endpoints (`169.254.169.254`, `metadata.google.internal`)
- Dangerous URI schemes (`file://`, `gopher://`, `dict://`, `ldap://`)
- Localhost hostnames and aliases

---

## 🧪 Testing

```bash
# Run the test suite
pytest tests/ -v
```

---

## 📄 License

For authorized security research only. Always obtain proper permission before testing.
