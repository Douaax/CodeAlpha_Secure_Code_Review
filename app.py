"""
VulnNotes — A deliberately vulnerable Flask notes application.

⚠️  WARNING: This app contains intentional security vulnerabilities for
educational purposes only. DO NOT deploy this to a production environment
or expose it on the public internet.

Audit target for: Task 3 — Secure Coding Review
"""

import hashlib
import os
import pickle
import sqlite3
import subprocess
import base64
from flask import (
    Flask, request, render_template, redirect, session,
    make_response, send_file, g
)
from markupsafe import Markup
import requests

app = Flask(__name__)

# VULN-04: Hardcoded secret key (CWE-798)
app.config['SECRET_KEY'] = 'super_secret_key_123'

# VULN-13: Insecure session cookie configuration (CWE-614, CWE-1004)
app.config['SESSION_COOKIE_SECURE'] = False
app.config['SESSION_COOKIE_HTTPONLY'] = False
app.config['SESSION_COOKIE_SAMESITE'] = None

# VULN-14: Hardcoded DB credentials (in real apps these would be DB passwords)
DB_PATH = 'notes.db'
ADMIN_API_KEY = 'sk_live_abc123_HARDCODED'

# ---------------------------------------------------------------- DB helpers

def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(error):
    db = g.pop('db', None)
    if db is not None:
        db.close()


def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password TEXT
    )""")
    c.execute("""CREATE TABLE IF NOT EXISTS notes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        owner TEXT,
        title TEXT,
        body TEXT
    )""")
    # Seed users (passwords stored as MD5 — VULN-05)
    c.execute("INSERT OR IGNORE INTO users (username, password) VALUES (?, ?)",
              ('alice', hashlib.md5(b'password123').hexdigest()))
    c.execute("INSERT OR IGNORE INTO users (username, password) VALUES (?, ?)",
              ('bob', hashlib.md5(b'qwerty').hexdigest()))
    c.execute("INSERT OR IGNORE INTO notes (owner, title, body) VALUES (?, ?, ?)",
              ('alice', 'Shopping list', 'milk, bread, eggs'))
    c.execute("INSERT OR IGNORE INTO notes (owner, title, body) VALUES (?, ?, ?)",
              ('bob',   'Secret',       'My bitcoin seed: ...'))
    conn.commit()
    conn.close()


# ---------------------------------------------------------------- routes

@app.route('/')
def index():
    return render_template('index.html', user=session.get('user'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')

        # VULN-01: SQL Injection — string concatenation (CWE-89)
        # VULN-05: Weak password hashing — MD5 (CWE-916)
        pwd_hash = hashlib.md5(password.encode()).hexdigest()
        query = (
            "SELECT * FROM users WHERE username = '" + username
            + "' AND password = '" + pwd_hash + "'"
        )
        cur = get_db().execute(query)
        row = cur.fetchone()

        if row:
            session['user'] = row['username']

            # VULN-12: Open redirect — trusts user-supplied "next" (CWE-601)
            next_url = request.args.get('next', '/notes')
            return redirect(next_url)

        return "Invalid login: " + username, 401

    return render_template('login.html')


@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect('/')


@app.route('/notes')
def notes():
    if 'user' not in session:
        return redirect('/login')

    # VULN-01 (again): SQL Injection via search parameter (CWE-89)
    search = request.args.get('q', '')
    query = "SELECT * FROM notes WHERE owner='" + session['user'] \
            + "' AND title LIKE '%" + search + "%'"
    rows = get_db().execute(query).fetchall()

    # VULN-02: XSS — passes raw user content to template with |safe filter
    notes_html = [
        {'id': r['id'], 'title': Markup(r['title']), 'body': Markup(r['body'])}
        for r in rows
    ]
    return render_template('notes.html', notes=notes_html)


@app.route('/note/<note_id>')
def view_note(note_id):
    if 'user' not in session:
        return redirect('/login')

    # VULN-08: IDOR — no check that the note belongs to the logged-in user (CWE-639)
    # VULN-01: SQL Injection in path parameter
    cur = get_db().execute("SELECT * FROM notes WHERE id=" + note_id)
    note = cur.fetchone()
    if not note:
        return "Not found", 404
    return f"<h1>{note['title']}</h1><div>{note['body']}</div>"


@app.route('/note/new', methods=['POST'])
def new_note():
    if 'user' not in session:
        return redirect('/login')

    # VULN-10: No CSRF token validated on state-changing request (CWE-352)
    title = request.form.get('title', '')
    body  = request.form.get('body', '')
    get_db().execute(
        "INSERT INTO notes (owner, title, body) VALUES (?, ?, ?)",
        (session['user'], title, body)
    )
    get_db().commit()
    return redirect('/notes')


@app.route('/ping')
def ping():
    """Diagnostic endpoint — pings a host."""
    # VULN-03: OS Command Injection — shell=True with user input (CWE-78)
    host = request.args.get('host', 'localhost')
    result = subprocess.check_output(
        'ping -c 1 ' + host, shell=True
    )
    return "<pre>" + result.decode(errors='replace') + "</pre>"


@app.route('/download')
def download():
    """Download a file from the docs directory."""
    # VULN-07: Path Traversal — no sanitization (CWE-22)
    filename = request.args.get('file', 'readme.txt')
    path = os.path.join('docs', filename)
    return send_file(path)


@app.route('/preview')
def preview():
    """Fetch a preview of an external URL."""
    # VULN-11: Server-Side Request Forgery — unrestricted URL (CWE-918)
    url = request.args.get('url', '')
    r = requests.get(url, timeout=5)
    return r.text[:500]


@app.route('/restore', methods=['POST'])
def restore():
    """Restore a serialized session blob."""
    # VULN-06: Insecure deserialization — pickle on untrusted data (CWE-502)
    blob = request.form.get('data', '')
    obj = pickle.loads(base64.b64decode(blob))
    return f"Restored: {obj}"


@app.route('/admin')
def admin():
    # VULN-15: Sensitive info disclosure — leaks API key (CWE-200)
    key = request.args.get('key', '')
    if key == ADMIN_API_KEY:
        return f"Welcome admin. The API key is {ADMIN_API_KEY}"
    return "Forbidden. Hint: key starts with sk_live_", 403


# ---------------------------------------------------------------- main

if __name__ == '__main__':
    init_db()
    # VULN-09: Debug mode enabled in shipped code (CWE-489)
    app.run(host='0.0.0.0', port=5000, debug=True)