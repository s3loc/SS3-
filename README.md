```markdown
# 🔍 SS3 — Security & OSINT Intelligence Framework

A modular OSINT and security intelligence framework for **passive/active reconnaissance**, data archiving, network relationship analysis, measurable risk scoring, and **actionable** security recommendations.

---

## ⚠️ Disclaimer & Legal Notice

This software is intended **only** for the following purposes:
- Educational and academic research
- Authorized penetration testing
- Corporate security assessments

**Unauthorized use is strictly prohibited.**  
Any use against systems, networks, or data without explicit permission is illegal and may result in criminal prosecution. The user accepts full responsibility for all risks and liabilities arising from their actions.

**The software is provided "AS IS"** without any warranties, express or implied. The developers shall not be held liable for any direct or indirect damages.

For full legal terms, refer to [`LEGAL_DISCLAIMER.md`](LEGAL_DISCLAIMER.md).

---

## ✨ Core Features

| Module | Description |
|--------|-------------|
| **🛡️ Sentinel Node** | WHOIS, DNS, subdomain scanning, HTTP security headers, SSL status. **Asynchronous port scanning + banner grabbing + CVE matching** |
| **🕸️ Council Mesh** | NetworkX-based relationship graphs, centrality/density analysis, port and technology nodes |
| **💾 Archivum Core** | Compression + encryption (Fernet), multi-hash (MD5/SHA-1/SHA-256/SHA-512/BLAKE2b), disk archiving |
| **📒 Ledger** | RSA-signed quantum-hardened hash chain, SQLite persistence, integrity and verification logs |
| **🎯 Grand Node** | Executive summary, risk score/level, finding counts, and **automated remediation recommendations** |
| **📊 Dashboard** | Flask-based API + HTML report generation, visual cards for security suggestions |

---

## 🏗️ Architecture

```
SS3_Main.py
├─ Sentinel_Node.py # OSINT + active scanning / CVE matching
├─ Archivum_Core.py # Archiving / encryption / hashing
├─ Council_Mesh.py # Network graph and relational analysis
├─ Ledger.py # Signing, chaining, and database
├─ Grand_Node.py # Summary, scoring, recommendations
└─ SS3_Dashboard.py # Flask API + HTML reporting
```

---

## 🚀 Installation

### Prerequisites
- Python 3.8 or higher
- pip (latest version)

### Step-by-Step Setup

1. **Create and activate a virtual environment:**
```bash
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
```

2. **Install dependencies:**
```bash
pip install -U pip wheel
pip install flask requests dnspython python-whois ipwhois beautifulsoup4 aiohttp networkx plotly pandas cryptography
```

3. **Optional: Shodan integration (requires API key):**
```bash
pip install shodan
```

### Environment Variables
```bash
export SHODAN_API_KEY="your_api_key_here"  # For Shodan integration
export FLASK_ENV="development"             # Development mode
```

---

## 🎮 Usage

### 1. Command Line Interface
```bash
python SS3_Main.py
# Enter target domain/IP when prompted: example.com
```

### 2. Web Dashboard
```bash
export FLASK_APP=SS3_Dashboard.py
flask run --host 0.0.0.0 --port 5000
```

**API Example:**
```bash
curl -X POST http://localhost:5000/run \
  -H "Content-Type: application/json" \
  -d '{"target": "example.com"}'
```

**Output:** `reports/SS3_Report_YYYYMMDD_HHMMSS_example.com.html`

---

## 📈 Outputs & Reporting

### Risk Metrics
- **Risk Score:** Normalized value between 0.0–1.0
- **Finding Levels:** Critical/High/Medium/Low classification
- **Summary Dashboard:** Visual and statistical overview

### Security Recommendations
- WAF configuration suggestions
- Port security (restrict 22/445/3389)
- DMARC/DKIM/SPF policy enforcement
- SSL/TLS improvements
- HTTP security headers (CSP, HSTS, X-Frame-Options)

### Active Scanning Results
- Open port list and service details
- Banner information and version detection
- Potential CVE matches

---

## 🔒 Security & Compliance

### Best Practices
- Run active scans **only** on authorized targets
- Maintain audit logs for all analyses
- Store API keys in `.env` files
- Use SSL/TLS in production

### Audit Logging
Log the following for each analysis:
- User and timestamp
- Target domain/IP
- Modules executed
- Risk score and findings summary

---

## 🌐 Production Deployment

### Gunicorn + Nginx
```bash
gunicorn SS3_Dashboard:app -w 4 -b 0.0.0.0:8080
```

### Log Management
```bash
# Using systemd service
journalctl -u ss3-service

# File-based logging
logrotate /etc/logrotate.d/ss3
```

---

## 🤝 Contributing

We welcome contributions! When developing new modules, please:

- Implement input validation and timeouts
- Display **usage warnings** for network operations
- Maintain the existing JSON reporting format
- Increase test coverage

### Contribution Process
1. Fork the repository and create a feature branch
2. Test your changes thoroughly
3. Open a PR and describe your modifications in detail

---

## 📄 License

This project is licensed under the MIT License. See [`LICENSE`](LICENSE) for details.

---

## 🆘 Support & Contact

- **Bug Reports:** GitHub Issues
- **Security Vulnerabilities:** Please report via private message
- **Documentation:** Check the [`docs/`](docs/) folder

---

![SS3 Framework](https://github.com/user-attachments/assets/2372e816-66c7-41a5-a1ec-1689a361c397)

> *"Knowledge is power, but it gains value only when used responsibly."*
```

SV...
