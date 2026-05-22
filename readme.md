# Task 3 — Secure Coding Review

> Cybersecurity Internship · Static analysis and manual review of a Flask web application

## 📋 Overview

This task involved auditing a Python/Flask web application for security
vulnerabilities using a combination of **static analysis tools** and
**manual code review**, then documenting findings with severity ratings,
CWE references, and remediation guidance.

## 🎯 What was done

1. Built a deliberately vulnerable Flask app (`vulnerable-app/`) as the audit target — `~160` LOC across `app.py` and 3 Jinja2 templates, with 15 intentional security flaws.
2. Scanned the codebase with three complementary tools:
   - **Bandit** — Python AST-based SAST scanner
   - **Semgrep** — Multi-framework pattern-matching scanner (304 rules)
   - **pip-audit** — Dependency CVE scanner against the PyPI Advisory Database
3. Performed manual code review for logic-level flaws that scanners cannot detect (IDOR, insecure cookie config, info disclosure).
4. Compiled findings into a formal report — `docs/FINDINGS.md`.

## 📊 Results at a glance

| Metric | Count |
|---|---|
| Application vulnerabilities found | **15** |
| Dependency CVEs found | **27** |
| Critical findings | 4 |
| High findings | 5 |
| Medium findings | 4 |
| Low findings | 2 |

Full breakdown: see **[`docs/FINDINGS.md`](docs/FINDINGS.md)**.

## 🗂️ Folder contents

| Path | Description |
|---|---|
| `vulnerable-app/` | The intentionally vulnerable Flask application (audit target) |
| `scans/` | Raw output from Bandit, Semgrep, and pip-audit |
| `docs/FINDINGS.md` | **The main deliverable** — formal findings report |
| `docs/screenshots/` | Evidence screenshots (scan output, exploit demos) |

## 🔧 Tools used

| Tool | Version | Purpose |
|---|---|---|
| Python | 3.13 | Application language |
| Flask | 2.0.1 (intentionally outdated) | Web framework |
| Bandit | latest | Python SAST |
| Semgrep | latest | Multi-framework SAST |
| pip-audit | latest | Dependency CVE scanner |

## 🚀 How to reproduce

```bash
# 1. Set up the vulnerable app
cd vulnerable-app
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# 2. Install audit tools
pip install bandit semgrep pip-audit

# 3. Run the three scanners (from inside vulnerable-app/)
bandit  -r . -x ./venv -f txt -o ../scans/bandit-report.txt
semgrep --config=auto . --exclude venv --text -o ../scans/semgrep-report.txt
pip-audit -r requirements.txt -f columns -o ../scans/pip-audit-report.txt

# 4. (Optional) Run the app to verify exploits manually
python app.py
# Browse http://127.0.0.1:5000 — login as alice / password123
```

## ⚠️ Safety notice

The application in `vulnerable-app/` is **deliberately insecure**. It must
only be run inside an isolated VM and must never be exposed to a public
network.

## 📚 Standards & references

- [OWASP Top 10 — 2021](https://owasp.org/Top10/)
- [CWE — Common Weakness Enumeration](https://cwe.mitre.org/)
- [OWASP ASVS v4.0](https://owasp.org/www-project-application-security-verification-standard/)

---

*Completed as part of the Cybersecurity Internship at CodeAlpha — Task 3.*
