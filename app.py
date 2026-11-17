"""API Notas: API REST vulnerable a proposito para el mini sprint DevSecOps.

NO desplegar ni exponer a una red. Se ejecuta solo en 127.0.0.1.
Cada vulnerabilidad esta marcada con un comentario [VULN] para poder
demostrarla y luego corregirla durante el sprint.
"""

import base64
import hashlib
import os
import sqlite3
import subprocess

import requests
import yaml
from flask import Flask, g, jsonify, request

import config

app = Flask(__name__)
app.config["SECRET_KEY"] = config.SECRET_KEY

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
FILES_DIR = os.path.join(BASE_DIR, "files")
DB_PATH = os.path.join(BASE_DIR, config.DATABASE_PATH)


# ---------------------------------------------------------------------------
# Base de datos
# ---------------------------------------------------------------------------
def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(_exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def hash_password(password):
    # [VULN] MD5 sin sal no es apto para almacenar contrasenas.
    return hashlib.md5(password.encode()).hexdigest()


def init_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    db = sqlite3.connect(DB_PATH)
    db.executescript(
        """
        DROP TABLE IF EXISTS users;
        DROP TABLE IF EXISTS notes;
        CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            email TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'user'
        );
        CREATE TABLE notes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            content TEXT NOT NULL
        );
        """
    )
    users = [
        (config.ADMIN_USERNAME, hash_password(config.ADMIN_PASSWORD), "admin@notas.local", "admin"),
        ("ana", hash_password("ana2026"), "ana@notas.local", "user"),
        ("luis", hash_password("luis2026"), "luis@notas.local", "user"),
    ]
    db.executemany("INSERT INTO users (username, password, email, role) VALUES (?, ?, ?, ?)", users)
    notes = [
        (1, "Credenciales del servidor", "Clave de respaldo del servidor: Respaldo#2026"),
        (2, "Lista de compras", "Leche, pan, cafe"),
        (3, "Pendientes", "Terminar el informe de DevSecOps"),
    ]
    db.executemany("INSERT INTO notes (user_id, title, content) VALUES (?, ?, ?)", notes)
    db.commit()
    db.close()


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------
@app.get("/")
def index():
    return jsonify(
        api="Notas API (vulnerable)",
        version="0.1.0",
        endpoints=[
            "GET  /api/health",
            "POST /api/login",
            "GET  /api/users",
            "GET  /api/users/search?name=",
            "GET  /api/notes?user_id=",
            "POST /api/notes",
            "GET  /api/greet?name=",
            "GET  /api/ping?host=",
            "POST /api/calc",
            "POST /api/import",
            "GET  /api/files?name=",
            "GET  /api/fetch?url=",
            "GET  /api/debug/config",
        ],
    )


@app.get("/api/health")
def health():
    return jsonify(status="ok")


@app.post("/api/login")
def login():
    data = request.get_json(silent=True) or {}
    username = data.get("username", "")
    password = hash_password(data.get("password", ""))
    # [VULN] Inyeccion SQL: la consulta se arma concatenando la entrada del usuario.
    query = "SELECT id, username, role FROM users WHERE username = '%s' AND password = '%s'" % (
        username,
        password,
    )
    user = get_db().execute(query).fetchone()
    if user is None:
        return jsonify(error="Credenciales invalidas"), 401
    # [VULN] Token predecible: solo base64 del usuario y la clave secreta.
    token = base64.b64encode(f"{user['username']}:{config.SECRET_KEY}".encode()).decode()
    return jsonify(message="Login correcto", user=dict(user), token=token)


@app.get("/api/users")
def list_users():
    # [VULN] Exposicion de datos sensibles: devuelve hashes de contrasenas sin autenticacion.
    rows = get_db().execute("SELECT * FROM users").fetchall()
    return jsonify([dict(r) for r in rows])


@app.get("/api/users/search")
def search_users():
    name = request.args.get("name", "")
    # [VULN] Inyeccion SQL en busqueda.
    query = f"SELECT id, username, email FROM users WHERE username LIKE '%{name}%'"
    rows = get_db().execute(query).fetchall()
    return jsonify([dict(r) for r in rows])


@app.get("/api/notes")
def list_notes():
    # [VULN] IDOR: cualquiera puede leer las notas de cualquier usuario.
    user_id = request.args.get("user_id", "1")
    rows = get_db().execute("SELECT * FROM notes WHERE user_id = ?", (user_id,)).fetchall()
    return jsonify([dict(r) for r in rows])


@app.post("/api/notes")
def create_note():
    data = request.get_json(silent=True) or {}
    db = get_db()
    cur = db.execute(
        "INSERT INTO notes (user_id, title, content) VALUES (?, ?, ?)",
        (data.get("user_id", 1), data.get("title", ""), data.get("content", "")),
    )
    db.commit()
    return jsonify(id=cur.lastrowid, message="Nota creada"), 201


@app.get("/api/greet")
def greet():
    name = request.args.get("name", "visitante")
    # [VULN] XSS reflejado: se devuelve HTML con la entrada sin escapar.
    return f"<html><body><h1>Hola, {name}</h1></body></html>"


@app.get("/api/ping")
def ping():
    host = request.args.get("host", "127.0.0.1")
    # [VULN] Inyeccion de comandos: shell=True con entrada del usuario.
    result = subprocess.run(
        f"ping -c 1 {host}", shell=True, capture_output=True, text=True, timeout=10
    )
    return jsonify(command=f"ping -c 1 {host}", output=result.stdout + result.stderr)


@app.post("/api/calc")
def calc():
    data = request.get_json(silent=True) or {}
    expression = data.get("expression", "0")
    # [VULN] eval() ejecuta cualquier codigo Python enviado por el cliente.
    return jsonify(expression=expression, result=str(eval(expression)))


@app.post("/api/import")
def import_yaml():
    # [VULN] Deserializacion insegura: yaml.load con Loader completo.
    data = yaml.load(request.get_data(as_text=True), Loader=yaml.Loader)
    return jsonify(imported=str(data))


@app.get("/api/files")
def read_file():
    name = request.args.get("name", "bienvenida.txt")
    # [VULN] Path traversal: no se valida el nombre (ej. ../config.py).
    path = os.path.join(FILES_DIR, name)
    with open(path, encoding="utf-8") as fh:
        return jsonify(name=name, content=fh.read())


@app.get("/api/fetch")
def fetch_url():
    url = request.args.get("url", "https://example.com")
    # [VULN] SSRF y verificacion TLS deshabilitada.
    resp = requests.get(url, timeout=5, verify=False)
    return jsonify(url=url, status=resp.status_code, body=resp.text[:500])


@app.get("/api/debug/config")
def debug_config():
    # [VULN] Endpoint de depuracion que expone la configuracion y los secretos.
    return jsonify(
        {k: getattr(config, k) for k in dir(config) if k.isupper()}
    )


if __name__ == "__main__":
    init_db()
    # [VULN] Modo debug activado (debugger de Werkzeug permite ejecutar codigo).
    app.run(host="127.0.0.1", port=5000, debug=config.DEBUG)
