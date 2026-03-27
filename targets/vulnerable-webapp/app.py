"""
Vulnerable Flask web application — intentionally insecure for security testing.
DO NOT deploy this to any real environment.
"""
import os
import subprocess

import psycopg2
import requests
from flask import Flask, request, jsonify, render_template_string

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'flask-secret-key')
app.config['DEBUG'] = True  # intentional: exposes debugger

DB_HOST = os.environ.get('DB_HOST', 'internal-db')
DB_USER = os.environ.get('DB_USER', 'dbuser')
DB_PASS = os.environ.get('DB_PASS', 'password')
DB_NAME = os.environ.get('DB_NAME', 'appdb')


def get_db():
    return psycopg2.connect(
        host=DB_HOST, user=DB_USER, password=DB_PASS, dbname=DB_NAME,
        connect_timeout=3
    )


@app.route('/')
def index():
    return jsonify({
        "service": "vulnerable-webapp",
        "endpoints": [
            "/search?q=   (SQLi)",
            "/greet?name= (XSS)",
            "/fetch?url=  (SSRF)",
            "/user/<id>   (IDOR)",
            "/upload      (unrestricted file upload)",
            "/ping?host=  (command injection)",
            "/debug       (env var leakage)",
            "/admin       (broken access control)",
        ]
    })


@app.route('/health')
def health():
    return jsonify({"status": "ok"})


# ─── SQL INJECTION ───────────────────────────────────────────────────────────
@app.route('/search')
def search():
    """CWE-89: SQL Injection — raw string interpolation into query."""
    q = request.args.get('q', '')
    try:
        conn = get_db()
        cur = conn.cursor()
        # Intentional SQLi: f-string directly into query
        cur.execute(f"SELECT id, name, email FROM users WHERE name LIKE '%{q}%'")
        rows = cur.fetchall()
        conn.close()
        return jsonify({"results": rows})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ─── CROSS-SITE SCRIPTING ─────────────────────────────────────────────────────
@app.route('/greet')
def greet():
    """CWE-79: Reflected XSS — name rendered without escaping."""
    name = request.args.get('name', 'World')
    # Intentional XSS: user input directly into HTML without escaping
    html = f"<html><body><h1>Hello, {name}!</h1></body></html>"
    return html


# ─── SERVER-SIDE REQUEST FORGERY ──────────────────────────────────────────────
@app.route('/fetch')
def fetch():
    """CWE-918: SSRF — fetches any URL without allowlist."""
    url = request.args.get('url', '')
    if not url:
        return jsonify({"error": "url parameter required"}), 400
    try:
        # Intentional SSRF: no allowlist, no scheme restriction, follows redirects
        resp = requests.get(url, timeout=5, allow_redirects=True)
        return resp.text, resp.status_code, {'Content-Type': resp.headers.get('Content-Type', 'text/plain')}
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ─── INSECURE DIRECT OBJECT REFERENCE ────────────────────────────────────────
@app.route('/user/<int:user_id>')
def get_user(user_id):
    """CWE-639: IDOR — no ownership check, any ID returns that user's data."""
    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute("SELECT id, name, email, ssn, credit_card FROM users WHERE id = %s", (user_id,))
        row = cur.fetchone()
        conn.close()
        if row:
            return jsonify({"id": row[0], "name": row[1], "email": row[2], "ssn": row[3], "credit_card": row[4]})
        return jsonify({"error": "user not found"}), 404
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ─── UNRESTRICTED FILE UPLOAD ─────────────────────────────────────────────────
@app.route('/upload', methods=['POST'])
def upload():
    """CWE-434: Unrestricted file upload — no type check, saves with original name."""
    f = request.files.get('file')
    if not f:
        return jsonify({"error": "no file"}), 400
    # Intentional: no extension or content-type validation
    save_path = f'/tmp/uploads/{f.filename}'
    os.makedirs('/tmp/uploads', exist_ok=True)
    f.save(save_path)
    return jsonify({"saved": save_path})


# ─── COMMAND INJECTION ────────────────────────────────────────────────────────
@app.route('/ping')
def ping():
    """CWE-78: OS Command Injection — host directly interpolated into shell command."""
    host = request.args.get('host', '127.0.0.1')
    # Intentional CMDi: shell=True with user-controlled input
    result = subprocess.run(
        f'ping -c 1 {host}',
        shell=True, capture_output=True, text=True, timeout=5
    )
    return jsonify({"stdout": result.stdout, "stderr": result.stderr})


# ─── SECRET / ENV LEAKAGE ─────────────────────────────────────────────────────
@app.route('/debug')
def debug():
    """CWE-215: Debug endpoint left in production — exposes all env vars."""
    return jsonify(dict(os.environ))


# ─── BROKEN ACCESS CONTROL ────────────────────────────────────────────────────
@app.route('/admin')
def admin():
    """CWE-862: Missing authorization check — no auth required."""
    return jsonify({
        "users": ["admin", "user1", "user2"],
        "db_password": os.environ.get('DB_PASS'),
        "secret_key": app.config['SECRET_KEY'],
    })


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
