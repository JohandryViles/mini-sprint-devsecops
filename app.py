"""API Notas: API REST remediada para el mini sprint DevSecOps."""

import ast
import operator
import os
import re
import secrets
import socket
import sqlite3
from functools import wraps
from pathlib import Path
from urllib.parse import urlparse

import requests
import yaml
from flask import Flask, g, jsonify, request
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer
from markupsafe import escape
from werkzeug.security import check_password_hash, generate_password_hash

import config

app = Flask(__name__)
app.config["SECRET_KEY"] = config.SECRET_KEY

BASE_DIR = Path(__file__).resolve().parent
FILES_DIR = (BASE_DIR / "files").resolve()
DB_PATH = BASE_DIR / config.DATABASE_PATH

TOKEN_MAX_AGE_SECONDS = 3600
ALLOWED_PING_HOSTS = {"127.0.0.1", "localhost"}
ALLOWED_FETCH_HOSTS = {"example.com"}
HOST_PATTERN = re.compile(r"^[a-zA-Z0-9.-]+$")

SAFE_BIN_OPS = {
    ast.Add: operator.add,
    ast.Sub: operator.sub,
    ast.Mult: operator.mul,
    ast.Div: operator.truediv,
    ast.Mod: operator.mod,
}
SAFE_UNARY_OPS = {
    ast.UAdd: operator.pos,
    ast.USub: operator.neg,
}


def _serializer() -> URLSafeTimedSerializer:
    return URLSafeTimedSerializer(app.config["SECRET_KEY"], salt="notas-api-auth")


def generate_token(user_row) -> str:
    payload = {
        "id": user_row["id"],
        "username": user_row["username"],
        "role": user_row["role"],
    }
    return _serializer().dumps(payload)


def get_current_user():
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return None
    token = auth_header.split(" ", 1)[1].strip()
    if not token:
        return None
    try:
        return _serializer().loads(token, max_age=TOKEN_MAX_AGE_SECONDS)
    except (BadSignature, SignatureExpired):
        return None


def require_auth(admin_only: bool = False):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            user = get_current_user()
            if user is None:
                return jsonify(error="No autorizado"), 401
            if admin_only and user.get("role") != "admin":
                return jsonify(error="Acceso denegado"), 403
            g.current_user = user
            return func(*args, **kwargs)

        return wrapper

    return decorator


def safe_eval_math(expression: str):
    tree = ast.parse(expression, mode="eval")

    def _eval(node):
        if isinstance(node, ast.Expression):
            return _eval(node.body)
        if isinstance(node, ast.Constant) and isinstance(node.value, (int, float)) and not isinstance(node.value, bool):
            return node.value
        if isinstance(node, ast.BinOp) and type(node.op) in SAFE_BIN_OPS:
            return SAFE_BIN_OPS[type(node.op)](_eval(node.left), _eval(node.right))
        if isinstance(node, ast.UnaryOp) and type(node.op) in SAFE_UNARY_OPS:
            return SAFE_UNARY_OPS[type(node.op)](_eval(node.operand))
        raise ValueError("Expresion no permitida")

    return _eval(tree)


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


def hash_password(password: str) -> str:
    return generate_password_hash(password)


def init_db():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
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
    admin_pwd = config.ADMIN_PASSWORD or secrets.token_urlsafe(16)
    ana_pwd = os.environ.get("DEMO_ANA_PASSWORD") or secrets.token_urlsafe(16)
    luis_pwd = os.environ.get("DEMO_LUIS_PASSWORD") or secrets.token_urlsafe(16)

    users = [
        (config.ADMIN_USERNAME, hash_password(admin_pwd), "admin@notas.local", "admin"),
        ("ana", hash_password(ana_pwd), "ana@notas.local", "user"),
        ("luis", hash_password(luis_pwd), "luis@notas.local", "user"),
    ]
    db.executemany("INSERT INTO users (username, password, email, role) VALUES (?, ?, ?, ?)", users)
    notes = [
        (1, "Mantenimiento del servidor", "Respaldo programado semanal"),
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
        api="Notas API",
        version="1.0.0",
        endpoints=[
            "GET  /api/health",
            "POST /api/login",
            "GET  /api/users",
            "GET  /api/users/search?name=",
            "GET  /api/notes",
            "POST /api/notes",
            "GET  /api/greet?name=",
            "GET  /api/ping?host=",
            "POST /api/calc",
            "POST /api/import",
            "GET  /api/files?name=",
            "GET  /api/fetch?url=",
        ],
    )


@app.get("/api/health")
def health():
    return jsonify(status="ok")


@app.post("/api/login")
def login():
    data = request.get_json(silent=True) or {}
    username = str(data.get("username", "")).strip()
    raw_password = str(data.get("password", ""))
    user = get_db().execute(
        "SELECT id, username, password, role FROM users WHERE username = ?",
        (username,),
    ).fetchone()
    if user is None or not check_password_hash(user["password"], raw_password):
        return jsonify(error="Credenciales invalidas"), 401
    token = generate_token(user)
    safe_user = {"id": user["id"], "username": user["username"], "role": user["role"]}
    return jsonify(message="Login correcto", user=safe_user, token=token)


@app.get("/api/users")
@require_auth(admin_only=True)
def list_users():
    rows = get_db().execute("SELECT id, username, email, role FROM users").fetchall()
    return jsonify([dict(r) for r in rows])


@app.get("/api/users/search")
@require_auth()
def search_users():
    name = request.args.get("name", "")
    rows = get_db().execute(
        "SELECT id, username, email FROM users WHERE username LIKE ?",
        (f"%{name}%",),
    ).fetchall()
    return jsonify([dict(r) for r in rows])


@app.get("/api/notes")
@require_auth()
def list_notes():
    rows = get_db().execute(
        "SELECT id, user_id, title, content FROM notes WHERE user_id = ?",
        (g.current_user["id"],),
    ).fetchall()
    return jsonify([dict(r) for r in rows])


@app.post("/api/notes")
@require_auth()
def create_note():
    data = request.get_json(silent=True) or {}
    title = str(data.get("title", "")).strip()
    content = str(data.get("content", "")).strip()
    db = get_db()
    cur = db.execute(
        "INSERT INTO notes (user_id, title, content) VALUES (?, ?, ?)",
        (g.current_user["id"], title, content),
    )
    db.commit()
    return jsonify(id=cur.lastrowid, message="Nota creada"), 201


@app.get("/api/greet")
def greet():
    name = escape(request.args.get("name", "visitante"))
    return f"<html><body><h1>Hola, {name}</h1></body></html>"


@app.get("/api/ping")
def ping():
    host = request.args.get("host", "127.0.0.1").strip()
    if not HOST_PATTERN.match(host) or host not in ALLOWED_PING_HOSTS:
        return jsonify(error="Host no permitido"), 400
    try:
        resolved_ip = socket.gethostbyname(host)
        return jsonify(host=host, resolved_ip=resolved_ip, status="reachable")
    except OSError:
        return jsonify(host=host, status="unreachable"), 502


@app.post("/api/calc")
def calc():
    data = request.get_json(silent=True) or {}
    expression = str(data.get("expression", "0")).strip()
    if len(expression) > 100:
        return jsonify(error="Expresion demasiado larga"), 400
    try:
        result = safe_eval_math(expression)
    except (ValueError, SyntaxError, ZeroDivisionError, TypeError):
        return jsonify(error="Expresion matematica invalida"), 400
    return jsonify(expression=expression, result=str(result))


@app.post("/api/import")
def import_yaml():
    try:
        data = yaml.safe_load(request.get_data(as_text=True))
    except yaml.YAMLError:
        return jsonify(error="YAML invalido"), 400
    return jsonify(imported=data)


@app.get("/api/files")
def read_file():
    name = request.args.get("name", "bienvenida.txt")
    safe_name = os.path.basename(name)
    if safe_name != name or not safe_name:
        return jsonify(error="Nombre de archivo no permitido"), 400
    candidate = (FILES_DIR / safe_name).resolve()
    if not candidate.is_relative_to(FILES_DIR) or not candidate.is_file():
        return jsonify(error="Archivo no encontrado"), 404
    return jsonify(name=safe_name, content=candidate.read_text(encoding="utf-8"))


@app.get("/api/fetch")
def fetch_url():
    url = request.args.get("url", "https://example.com").strip()
    parsed = urlparse(url)
    if parsed.scheme != "https" or parsed.hostname not in ALLOWED_FETCH_HOSTS:
        return jsonify(error="URL o host no permitido"), 400
    try:
        resp = requests.get(url, timeout=5, verify=True)
    except requests.RequestException:
        return jsonify(error="Error al consultar el recurso externo"), 502
    return jsonify(url=url, status=resp.status_code, body=resp.text[:500])


@app.get("/api/debug/config")
def debug_config():
    return jsonify(error="Endpoint deshabilitado por seguridad"), 403


if __name__ == "__main__":
    init_db()
    app.run(host="127.0.0.1", port=5000, debug=False)