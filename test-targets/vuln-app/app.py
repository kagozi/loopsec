"""
Deliberately Vulnerable Flask App — FOR TESTING ONLY
DO NOT deploy this anywhere public. It contains intentional security flaws.

Vulnerabilities included:
1. SQL Injection (CWE-89)
2. Cross-Site Scripting / XSS (CWE-79)
3. Hardcoded credentials (CWE-798)
4. Command Injection (CWE-78)
5. Path Traversal (CWE-22)
6. Insecure Deserialization (CWE-502)
7. Missing authentication
8. Information exposure via error messages
"""

import os
import pickle
import sqlite3
import subprocess
import base64

from flask import Flask, request, jsonify, render_template_string

app = Flask(__name__)

# ──────────────────────────────────────────────
# VULN 1: Hardcoded credentials (CWE-798)
# ──────────────────────────────────────────────
DATABASE_PASSWORD = "admin123"
SECRET_API_KEY = "sk-1234567890abcdef"
DB_CONNECTION_STRING = "postgresql://admin:P@ssw0rd!@db.internal:5432/prod"


def get_db():
    db = sqlite3.connect("vuln_app.db")
    db.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT,
            password TEXT,
            email TEXT,
            role TEXT DEFAULT 'user'
        )
    """)
    db.execute("""
        CREATE TABLE IF NOT EXISTS notes (
            id INTEGER PRIMARY KEY,
            user_id INTEGER,
            title TEXT,
            content TEXT
        )
    """)
    # Seed data
    db.execute("INSERT OR IGNORE INTO users (id, username, password, email, role) VALUES (1, 'admin', 'admin123', 'admin@test.com', 'admin')")
    db.execute("INSERT OR IGNORE INTO users (id, username, password, email, role) VALUES (2, 'alice', 'password', 'alice@test.com', 'user')")
    db.execute("INSERT OR IGNORE INTO notes (id, user_id, title, content) VALUES (1, 1, 'Secret Note', 'This is confidential admin data')")
    db.execute("INSERT OR IGNORE INTO notes (id, user_id, title, content) VALUES (2, 2, 'Alice Note', 'Hello world')")
    db.commit()
    return db


# ──────────────────────────────────────────────
# VULN 2: SQL Injection (CWE-89)
# ──────────────────────────────────────────────
@app.route("/api/login", methods=["POST"])
def login():
    username = request.form.get("username", "")
    password = request.form.get("password", "")

    db = get_db()
    # BAD: String concatenation in SQL query
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
    cursor = db.execute(query)
    user = cursor.fetchone()

    if user:
        return jsonify({"status": "ok", "user": user[1], "role": user[4]})
    return jsonify({"status": "error", "message": "Invalid credentials"}), 401


@app.route("/api/users", methods=["GET"])
def search_users():
    search = request.args.get("q", "")

    db = get_db()
    # FIX: Use parameterized query to prevent SQL injection
    query = "SELECT id, username, email FROM users WHERE username LIKE ?"
    cursor = db.execute(query, (f'%{search}%',))
    users = [{"id": r[0], "username": r[1], "email": r[2]} for r in cursor.fetchall()]

    return jsonify(users)


# ──────────────────────────────────────────────
# VULN 3: Cross-Site Scripting (CWE-79)
# ──────────────────────────────────────────────
@app.route("/search")
def search_page():
    query = request.args.get("q", "")
    # BAD: Reflecting user input without escaping
    html = f"""
    <html>
    <body>
        <h1>Search Results</h1>
        <p>You searched for: {query}</p>
        <form action="/search" method="get">
            <input name="q" value="{query}" />
            <button type="submit">Search</button>
        </form>
    </body>
    </html>
    """
    return render_template_string(html)


@app.route("/api/notes", methods=["GET"])
def get_notes():
    user_id = request.args.get("user_id", "1")

    db = get_db()
    # BAD: No authorization check — any user can read any user's notes (IDOR)
    query = f"SELECT * FROM notes WHERE user_id = {user_id}"
    cursor = db.execute(query)
    notes = [{"id": r[0], "title": r[2], "content": r[3]} for r in cursor.fetchall()]

    return jsonify(notes)


# ──────────────────────────────────────────────
# VULN 4: Command Injection (CWE-78)
# ──────────────────────────────────────────────
@app.route("/api/ping", methods=["GET"])
def ping():
    host = request.args.get("host", "localhost")

    # BAD: Unsanitized user input in shell command
    result = subprocess.check_output(f"ping -c 1 {host}", shell=True, text=True)
    return jsonify({"output": result})


@app.route("/api/lookup", methods=["POST"])
def dns_lookup():
    domain = request.json.get("domain", "") if request.json else ""

    # BAD: Command injection via os.popen
    output = os.popen(f"nslookup {domain}").read()
    return jsonify({"result": output})


# ──────────────────────────────────────────────
# VULN 5: Path Traversal (CWE-22)
# ──────────────────────────────────────────────
@app.route("/api/files", methods=["GET"])
def read_file():
    filename = request.args.get("name", "")

    # BAD: No path validation — allows ../../etc/passwd
    filepath = os.path.join("uploads", filename)
    try:
        with open(filepath, "r") as f:
            content = f.read()
        return jsonify({"filename": filename, "content": content})
    except Exception as e:
        # BAD: Exposing internal error details (CWE-209)
        return jsonify({"error": str(e), "path": filepath}), 500


# ──────────────────────────────────────────────
# VULN 6: Insecure Deserialization (CWE-502)
# ──────────────────────────────────────────────
@app.route("/api/import", methods=["POST"])
def import_data():
    data = request.form.get("data", "")

    # BAD: Deserializing untrusted user input with pickle
    try:
        decoded = base64.b64decode(data)
        obj = pickle.loads(decoded)
        return jsonify({"status": "imported", "type": str(type(obj))})
    except Exception as e:
        return jsonify({"error": str(e)}), 400


# ──────────────────────────────────────────────
# VULN 7: Information Exposure (CWE-200)
# ──────────────────────────────────────────────
@app.route("/api/debug")
def debug_info():
    # BAD: Exposing environment variables and internal config
    return jsonify({
        "env": dict(os.environ),
        "db_password": DATABASE_PASSWORD,
        "api_key": SECRET_API_KEY,
        "python_path": os.sys.path,
        "cwd": os.getcwd(),
    })


@app.route("/")
def index():
    return render_template_string("""
    <html>
    <head><title>VulnApp — Test Target</title></head>
    <body>
        <h1>VulnApp — Deliberately Vulnerable</h1>
        <p>This app contains intentional security vulnerabilities for testing.</p>
        <h3>Endpoints:</h3>
        <ul>
            <li>POST /api/login — SQL Injection</li>
            <li>GET /api/users?q= — SQL Injection</li>
            <li>GET /search?q= — XSS</li>
            <li>GET /api/notes?user_id= — IDOR</li>
            <li>GET /api/ping?host= — Command Injection</li>
            <li>POST /api/lookup — Command Injection</li>
            <li>GET /api/files?name= — Path Traversal</li>
            <li>POST /api/import — Insecure Deserialization</li>
            <li>GET /api/debug — Info Exposure</li>
        </ul>
    </body>
    </html>
    """)


if __name__ == "__main__":
    os.makedirs("uploads", exist_ok=True)
    app.run(host="0.0.0.0", port=5003, debug=True)
