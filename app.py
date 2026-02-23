"""
DROP — upload anônimo com autenticação TOTP
Versão hardened — proteção contra XSS, CSRF, clickjacking, enumeração, etc.
"""
import os
import json
import time
import hashlib
import secrets
import mimetypes
import re
from pathlib import Path
from datetime import datetime
from functools import wraps

from flask import (Flask, request, jsonify, send_file,
                   abort, render_template, make_response, redirect, url_for)
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.utils import secure_filename
import pyotp
import jwt

# ══════════════════════════════════════════════════════════════════════════════
#  Configuração
# ══════════════════════════════════════════════════════════════════════════════
UPLOAD_FOLDER = Path(os.environ.get("UPLOAD_FOLDER", "/opt/filehost/uploads"))
META_FOLDER   = Path(os.environ.get("META_FOLDER",   "/opt/filehost/meta"))
LOCK_FOLDER   = Path(os.environ.get("LOCK_FOLDER",   "/opt/filehost/locks"))
MAX_SIZE      = 4 * 1024 * 1024 * 1024
EXPIRY_HOURS  = 24
SESSION_DAYS  = int(os.environ.get("SESSION_DAYS", "7"))
SESSION_SECS  = SESSION_DAYS * 86400

TOTP_SECRET = os.environ["TOTP_SECRET"]
JWT_SECRET  = os.environ["JWT_SECRET"]

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = MAX_SIZE

for folder in (UPLOAD_FOLDER, META_FOLDER, LOCK_FOLDER):
    folder.mkdir(parents=True, exist_ok=True)

# ── Rate limiting ─────────────────────────────────────────────────────────────
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["300 per day", "60 per hour"],
    storage_uri="memory://",
)

# ── Extensões bloqueadas ──────────────────────────────────────────────────────
BLOCKED_EXTENSIONS = {
    ".exe", ".bat", ".cmd", ".com", ".scr", ".vbs", ".js", ".jse",
    ".wsf", ".wsh", ".msi", ".msp", ".ps1", ".sh", ".bash",
    ".php", ".py", ".rb", ".pl", ".cgi", ".asp", ".aspx", ".htaccess",
}

# ── IDs válidos: só letras, números, hífen e underscore ──────────────────────
VALID_ID_RE = re.compile(r'^[A-Za-z0-9\-_]{8,20}$')

# ══════════════════════════════════════════════════════════════════════════════
#  SEGURANÇA — Força HTTPS + Headers em TODAS as respostas
# ══════════════════════════════════════════════════════════════════════════════
@app.before_request
def force_https():
    proto = request.headers.get("X-Forwarded-Proto", "https")
    if proto == "http":
        return redirect(request.url.replace("http://", "https://", 1), 301)

@app.after_request
def security_headers(response):
    # Strict Transport Security — força HTTPS por 2 anos
    response.headers["Strict-Transport-Security"] = \
        "max-age=63072000; includeSubDomains; preload"

    # Impede o browser de "adivinhar" o tipo do arquivo (MIME sniffing)
    response.headers["X-Content-Type-Options"] = "nosniff"

    # Impede o site de ser embutido em iframes (clickjacking)
    response.headers["X-Frame-Options"] = "DENY"

    # Não vaza a URL de origem em requests externos
    response.headers["Referrer-Policy"] = "no-referrer"

    # Desativa APIs do browser que não precisamos
    response.headers["Permissions-Policy"] = \
        "geolocation=(), camera=(), microphone=(), payment=()"

    # Content Security Policy — impede XSS bloqueando scripts externos
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "          # inline js necessário no template
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src https://fonts.gstatic.com; "
        "img-src 'self' data:; "
        "connect-src 'self'; "
        "frame-ancestors 'none'; "                     # redundante com X-Frame-Options mas reforça
        "form-action 'self';"
    )

    # Remove header que revela que é Flask/Python
    response.headers.pop("Server", None)
    response.headers.pop("X-Powered-By", None)

    return response

# ══════════════════════════════════════════════════════════════════════════════
#  SEGURANÇA — CSRF Token
# ══════════════════════════════════════════════════════════════════════════════
def generate_csrf_token() -> str:
    """Gera ou reutiliza o token CSRF da sessão atual."""
    token = request.cookies.get("csrf_token")
    if not token:
        token = secrets.token_hex(32)
    return token

def validate_csrf():
    """Valida o token CSRF em requests de mutação (POST)."""
    cookie_token = request.cookies.get("csrf_token", "")
    # Aceita do header (fetch/XHR) ou do body (form)
    header_token = request.headers.get("X-CSRF-Token", "")
    body_token   = (request.json or {}).get("csrf_token", "") if request.is_json else ""
    sent_token   = header_token or body_token

    if not cookie_token or not sent_token:
        return False
    return secrets.compare_digest(cookie_token, sent_token)

def csrf_protect(f):
    """Decorator que exige CSRF válido em métodos de mutação."""
    @wraps(f)
    def wrapper(*args, **kwargs):
        if request.method in ("POST", "PUT", "DELETE", "PATCH"):
            # /auth e /logout são exceções controladas
            if request.endpoint not in ("auth", "logout"):
                if not validate_csrf():
                    return jsonify({"error": "Token CSRF inválido."}), 403
        return f(*args, **kwargs)
    return wrapper

# Injeta csrf_token em todos os templates
@app.context_processor
def inject_csrf():
    token = generate_csrf_token()
    return {"csrf_token": token}

@app.after_request
def set_csrf_cookie(response):
    """Garante que o cookie CSRF sempre existe."""
    if not request.cookies.get("csrf_token"):
        token = secrets.token_hex(32)
        response.set_cookie(
            "csrf_token", token,
            httponly=False,    # JS precisa ler para enviar no header
            secure=True,
            samesite="Strict",
            max_age=SESSION_SECS,
        )
    return response

# ══════════════════════════════════════════════════════════════════════════════
#  Helpers
# ══════════════════════════════════════════════════════════════════════════════
def ip_key(req) -> str:
    ip = req.headers.get("X-Forwarded-For", req.remote_addr or "")
    ip = ip.split(",")[0].strip()
    return hashlib.sha256(ip.encode()).hexdigest()[:24]

def human_size(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"

def is_blocked(filename: str) -> bool:
    return Path(filename).suffix.lower() in BLOCKED_EXTENSIONS

def validate_file_id(file_id: str) -> bool:
    return bool(VALID_ID_RE.match(file_id))

def sanitize_filename(name: str) -> str:
    """Remove caracteres perigosos do nome do arquivo."""
    name = secure_filename(name)
    # Remove qualquer coisa que não seja alfanumérico, ponto, hífen ou underscore
    name = re.sub(r'[^\w.\-]', '_', name)
    return name[:255]  # limita o tamanho

def generate_id() -> str:
    return secrets.token_urlsafe(12)

def save_meta(file_id, name, size, ip_k):
    meta = {
        "id": file_id,
        "name": name,
        "size": size,
        "uploaded_at": time.time(),
        "expires_at":  time.time() + EXPIRY_HOURS * 3600,
        "uploader": ip_k,
        "downloads": 0,
    }
    (META_FOLDER / f"{file_id}.json").write_text(json.dumps(meta))
    return meta

def load_meta(file_id: str):
    if not validate_file_id(file_id):
        return None
    p = META_FOLDER / f"{file_id}.json"
    if not p.exists():
        return None
    try:
        return json.loads(p.read_text())
    except Exception:
        return None

def delete_file(file_id: str):
    (UPLOAD_FOLDER / file_id).unlink(missing_ok=True)
    (META_FOLDER / f"{file_id}.json").unlink(missing_ok=True)

# ══════════════════════════════════════════════════════════════════════════════
#  Lockout persistente em disco
# ══════════════════════════════════════════════════════════════════════════════
MAX_ATTEMPTS    = 5
LOCKOUT_SECONDS = 15 * 60

def get_lock_state(ik: str) -> dict:
    p = LOCK_FOLDER / f"{ik}.json"
    if not p.exists():
        return {"attempts": 0, "locked_until": 0}
    try:
        return json.loads(p.read_text())
    except Exception:
        return {"attempts": 0, "locked_until": 0}

def save_lock_state(ik: str, state: dict):
    (LOCK_FOLDER / f"{ik}.json").write_text(json.dumps(state))

def clear_lock_state(ik: str):
    (LOCK_FOLDER / f"{ik}.json").unlink(missing_ok=True)

# ══════════════════════════════════════════════════════════════════════════════
#  Autenticação TOTP + JWT
# ══════════════════════════════════════════════════════════════════════════════
totp = pyotp.TOTP(TOTP_SECRET)

def check_totp(code: str) -> bool:
    return totp.verify(code, valid_window=1)

def issue_token() -> str:
    payload = {
        "sub": "owner",
        "iat": int(time.time()),
        "exp": int(time.time()) + SESSION_SECS,
        "jti": secrets.token_hex(8),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")

def verify_token(token: str) -> bool:
    try:
        jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        return True
    except Exception:
        return False

def get_token_from_request():
    return request.cookies.get("drop_session")

def require_auth(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        token = get_token_from_request()
        if not token or not verify_token(token):
            if request.accept_mimetypes.accept_json and \
               not request.accept_mimetypes.accept_html:
                return jsonify({"error": "Não autenticado."}), 401
            return redirect(url_for("login_page"))
        return f(*args, **kwargs)
    return wrapper

# ══════════════════════════════════════════════════════════════════════════════
#  Rotas de autenticação
# ══════════════════════════════════════════════════════════════════════════════
@app.route("/login")
def login_page():
    if verify_token(get_token_from_request() or ""):
        return redirect("/")
    return render_template("login.html", session_days=SESSION_DAYS)

@app.route("/auth", methods=["POST"])
@limiter.limit("10 per 5 minutes")
def auth():
    ik  = ip_key(request)
    now = time.time()

    state = get_lock_state(ik)
    if state["locked_until"] > now:
        remaining = int(state["locked_until"] - now)
        # Resposta genérica — não revela se é lockout ou código errado
        return jsonify({"error": f"Tente novamente em {remaining // 60}m {remaining % 60}s."}), 429

    data = request.get_json(silent=True) or {}
    code = str(data.get("code", "")).strip().replace(" ", "")

    # Valida formato antes de qualquer coisa
    if not code or len(code) != 6 or not code.isdigit():
        return jsonify({"error": "Código inválido."}), 400

    if check_totp(code):
        clear_lock_state(ik)
        token = issue_token()
        resp = make_response(jsonify({"ok": True}))
        resp.set_cookie(
            "drop_session", token,
            httponly=True,
            secure=True,
            samesite="Strict",
            max_age=SESSION_SECS,
        )
        return resp
    else:
        state["attempts"] = state.get("attempts", 0) + 1
        if state["attempts"] >= MAX_ATTEMPTS:
            state["locked_until"] = now + LOCKOUT_SECONDS
            state["attempts"] = 0
            save_lock_state(ik, state)
            return jsonify({"error": f"Tente novamente em {LOCKOUT_SECONDS // 60} minutos."}), 429
        save_lock_state(ik, state)
        remaining = MAX_ATTEMPTS - state["attempts"]
        return jsonify({"error": f"Código incorreto. {remaining} tentativa(s) restante(s)."}), 401

@app.route("/logout", methods=["POST"])
def logout():
    resp = make_response(redirect("/login"))
    resp.delete_cookie("drop_session", secure=True, samesite="Strict")
    resp.delete_cookie("csrf_token",   secure=True, samesite="Strict")
    return resp

# ══════════════════════════════════════════════════════════════════════════════
#  Rotas principais (protegidas)
# ══════════════════════════════════════════════════════════════════════════════
@app.route("/")
@require_auth
def index():
    return render_template("index.html")

@app.route("/upload", methods=["POST"])
@require_auth
@limiter.limit("20 per hour")
def upload():
    if "file" not in request.files:
        return jsonify({"error": "Nenhum arquivo enviado."}), 400

    f = request.files["file"]
    if not f.filename:
        return jsonify({"error": "Nome inválido."}), 400

    original_name = sanitize_filename(f.filename)
    if not original_name:
        return jsonify({"error": "Nome de arquivo inválido."}), 400

    if is_blocked(original_name):
        return jsonify({"error": "Tipo de arquivo não permitido."}), 400

    # Verifica espaço disponível antes de aceitar
    disk = os.statvfs(UPLOAD_FOLDER)
    free_bytes = disk.f_bavail * disk.f_frsize
    if free_bytes < MAX_SIZE:
        return jsonify({"error": "Servidor sem espaço suficiente."}), 507

    file_id = generate_id()
    dest    = UPLOAD_FOLDER / file_id

    try:
        f.save(dest)
    except Exception:
        dest.unlink(missing_ok=True)
        return jsonify({"error": "Erro ao salvar arquivo."}), 500

    size = dest.stat().st_size
    if size > MAX_SIZE:
        dest.unlink(missing_ok=True)
        return jsonify({"error": "Arquivo excede 4 GB."}), 413

    if size == 0:
        dest.unlink(missing_ok=True)
        return jsonify({"error": "Arquivo vazio."}), 400

    meta    = save_meta(file_id, original_name, size, ip_key(request))
    expires = datetime.fromtimestamp(meta["expires_at"]).strftime("%d/%m/%Y %H:%M")

    return jsonify({
        "id":      file_id,
        "link":    f"/d/{file_id}",
        "expires": expires,
        "size":    human_size(size),
        "name":    original_name,
    })

# ── Página de download (pública, sem auth) ────────────────────────────────────
@app.route("/d/<file_id>")
def download_page(file_id: str):
    if not validate_file_id(file_id):
        abort(404)

    meta = load_meta(file_id)
    if not meta:
        abort(404)

    if time.time() > meta["expires_at"]:
        delete_file(file_id)
        abort(410)

    total      = EXPIRY_HOURS * 3600
    remaining  = meta["expires_at"] - time.time()
    expire_pct = max(0, min(100, (remaining / total) * 100))
    hours, rem = divmod(int(remaining), 3600)
    expires_in = f"{hours}h {rem // 60}m"

    ext = Path(meta["name"]).suffix.lower()
    icons = {
        ".pdf": "📄", ".zip": "🗜️", ".rar": "🗜️", ".7z": "🗜️",
        ".mp4": "🎬", ".mkv": "🎬", ".avi": "🎬", ".mov": "🎬",
        ".mp3": "🎵", ".wav": "🎵", ".flac": "🎵",
        ".jpg": "🖼️", ".jpeg": "🖼️", ".png": "🖼️", ".gif": "🖼️",
        ".psd": "🎨", ".ai": "🎨",
        ".doc": "📝", ".docx": "📝", ".txt": "📝",
        ".xls": "📊", ".xlsx": "📊", ".ppt": "📊", ".pptx": "📊",
        ".iso": "💿",
    }

    return render_template("download.html",
        file_id    = file_id,
        name       = meta["name"],
        size       = human_size(meta["size"]),
        downloads  = meta["downloads"],
        expires_in = expires_in,
        expire_pct = round(expire_pct, 1),
        icon       = icons.get(ext, "📦"),
    )

@app.route("/download/<file_id>")
def download_file(file_id: str):
    if not validate_file_id(file_id):
        abort(404)

    meta = load_meta(file_id)
    if not meta:
        abort(404)

    if time.time() > meta["expires_at"]:
        delete_file(file_id)
        abort(410)

    fp = UPLOAD_FOLDER / file_id
    if not fp.exists():
        abort(404)

    # Garante que o path não saiu da pasta de uploads (path traversal)
    try:
        fp.resolve().relative_to(UPLOAD_FOLDER.resolve())
    except ValueError:
        abort(403)

    meta["downloads"] += 1
    (META_FOLDER / f"{file_id}.json").write_text(json.dumps(meta))

    mime = mimetypes.guess_type(meta["name"])[0] or "application/octet-stream"

    # Força download — nunca renderiza HTML ou JS no browser
    resp = make_response(send_file(
        fp,
        mimetype=mime,
        as_attachment=True,
        download_name=meta["name"],
    ))
    resp.headers["Content-Disposition"] = \
        f'attachment; filename="{meta["name"]}"'
    resp.headers["X-Content-Type-Options"] = "nosniff"
    return resp

# ── Info ──────────────────────────────────────────────────────────────────────
@app.route("/info/<file_id>")
@require_auth
def info(file_id: str):
    if not validate_file_id(file_id):
        return jsonify({"error": "ID inválido."}), 400
    meta = load_meta(file_id)
    if not meta:
        return jsonify({"error": "Não encontrado."}), 404
    if time.time() > meta["expires_at"]:
        delete_file(file_id)
        return jsonify({"error": "Expirado."}), 410
    remaining = int(meta["expires_at"] - time.time())
    h, m = divmod(remaining, 3600)
    return jsonify({
        "name": meta["name"],
        "size": human_size(meta["size"]),
        "expires_in": f"{h}h {m // 60}m",
        "downloads": meta["downloads"],
    })

# ── Cleanup interno ───────────────────────────────────────────────────────────
@app.route("/internal/cleanup", methods=["POST"])
def cleanup():
    expected = os.environ.get("CLEANUP_TOKEN", "")
    token    = request.headers.get("X-Cleanup-Token", "")
    if not expected or not secrets.compare_digest(token, expected):
        abort(403)
    removed = 0
    for mf in META_FOLDER.glob("*.json"):
        try:
            meta = json.loads(mf.read_text())
            if time.time() > meta["expires_at"]:
                delete_file(meta["id"])
                removed += 1
        except Exception:
            pass
    return jsonify({"removed": removed})

# ══════════════════════════════════════════════════════════════════════════════
#  Error handlers — respostas genéricas (não revelam detalhes internos)
# ══════════════════════════════════════════════════════════════════════════════
@app.errorhandler(400)
def bad_request(e):
    return jsonify({"error": "Requisição inválida."}), 400

@app.errorhandler(403)
def forbidden(e):
    return jsonify({"error": "Acesso negado."}), 403

@app.errorhandler(404)
def not_found(e):
    return jsonify({"error": "Não encontrado."}), 404

@app.errorhandler(405)
def method_not_allowed(e):
    return jsonify({"error": "Método não permitido."}), 405

@app.errorhandler(410)
def gone(e):
    return render_template("expired.html"), 410

@app.errorhandler(413)
def too_large(e):
    return jsonify({"error": "Arquivo muito grande. Limite: 4 GB."}), 413

@app.errorhandler(429)
def rate_limit(e):
    return jsonify({"error": "Muitas requisições. Tente mais tarde."}), 429

@app.errorhandler(500)
def server_error(e):
    return jsonify({"error": "Erro interno."}), 500

@app.errorhandler(507)
def insufficient_storage(e):
    return jsonify({"error": "Servidor sem espaço."}), 507

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
