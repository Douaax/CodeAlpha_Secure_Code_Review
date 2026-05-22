# VulnNotes — Deliberately Vulnerable Flask App

A small notes/login web app planted with **15 intentional security
vulnerabilities** for use as a secure-code-review training target.

## ⚠️ Warning
Do **not** deploy this app to the public internet. It is intentionally
unsafe and will be trivially exploited. Run it only in an isolated VM or
container.

## Run locally (Kali / Ubuntu)

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python app.py
# open http://127.0.0.1:5000
```

Seed accounts:

| user  | password    |
|-------|-------------|
| alice | password123 |
| bob   | qwerty      |

## Endpoints

| Route             | Purpose                          |
|-------------------|----------------------------------|
| `/login`          | Authenticate                     |
| `/notes`          | List & create notes              |
| `/note/<id>`      | View a single note               |
| `/ping?host=`     | Network diagnostic ping          |
| `/download?file=` | Download from `docs/`            |
| `/preview?url=`   | Fetch an external URL preview    |
| `/restore`        | Restore a serialised blob (POST) |
| `/admin?key=`     | Admin panel                      |

The vulnerabilities are documented in `../docs/FINDINGS.md` after the
secure-code review is performed.