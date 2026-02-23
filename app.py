# DROP — upload anônimo com autenticação TOTP (HARDENED v3)
# Base: ChatGPT simplificado + correções das 5 falhas críticas

import os
import json
import time
import hashlib
import secrets
import mimetypes
import re
import threading
from pathlib import Path
from datetime import datetime
from functools import wraps

from flask import (
    Flask, request, jsonify, send_file,
    abort, render_template, make_response,
    redirect, url_for
)
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.utils import secure_filename
import pyotp
import jwt

# ─────────────────────────────────────────────────────────────
# CONFIG
# ─────────────────────────────────────────────────────────────
UPLOAD_FOLDER = Path(os.environ.get("UPLOAD_FOLDER", "/opt/filehost/uploads"))
META_FOLDER   = Path(os.environ.get("META_FOLDER",   "/opt/filehost/meta"))
LOCK_FOLDER   = Path(os.environ.get("LOCK_FOLDER",   "/opt/filehost/locks"))

MAX_SIZE         = 4 * 1024 * 1024 * 1024   # 4 GB por arquivo
MAX_DISK_USAGE   = 100 * 1024 * 1024 * 1024  # 100 GB total no servidor
MAX_UPLOADS_PER_IP = 20                       # max arquivos por IP ativos ao mesmo tempo
EXPIRY_HOURS     = 24
SESSION_DAYS     = int(os.environ.get("SESSION_DAYS", "7"))
SESSION_SECS     = SESSION_DAYS * 86400

# FIX 2: Lockout persistente — sobrevive a reinicialização
MAX_ATTEMPTS    = 5
LOCKOUT_SECONDS = 15 * 60

TOTP_SECRET = os.environ["TOTP_SECRET"]
JWT_SECRET  = os.environ["JWT_SECRET"]

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = MAX_SIZE

for folder in (UPLOAD_FOLDER, META_FOLDER, LOCK_FOLDER):
    folder.mkdir(parents=True, exist_ok=True)

# ─────────────────────────────────────────────────────────────
# RATE LIMIT
# ─────────────────────────────────────────────────────────────
limiter = Limiter(get_remote_address, app=app,
                  default_limits=["300/day", "60/hour"],
                  storage_uri="memory://")

# ─────────────────────────────────────────────────────────────
# HEADERS DE SEGURANÇA
# ─────────────────────────────────────────────────────────────
@app.after_request
def security_headers(response):
    response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains; preload"
    response.headers["X-Content-Type-Options"]    = "nosniff"
    response.headers["X-Frame-Options"]           = "DENY"
    response.headers["Referrer-Policy"]           = "no-referrer"
    response.headers["Permissions-Policy"]        = "geolocation=(), camera=(), microphone=(), payment=()"
    # FIX 1: CSP sem unsafe-inline — scripts movidos para nonce
    nonce = getattr(request, "_csp_nonce", "")
    response.headers["Content-Security-Policy"] = (
        f"default-src 'self'; "
        f"script-src 'self' 'nonce-{nonce}'; "
        f"style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        f"font-src https://fonts.gstatic.com; "
        f"img-src 'self' data:; "
        f"connect-src 'self'; "
        f"frame-ancestors 'none'; "
        f"form-action 'self';"
    )
    response.headers.pop("Server", None)
    response.headers.pop("X-Powered-By", None)
    return response

@app.before_request
def generate_nonce():
    request._csp_nonce = secrets.token_urlsafe(16)

@app.context_processor
def inject_nonce():
    return {"csp_nonce": getattr(request, "_csp_nonce", "")}

# ─────────────────────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────────────────────
VALID_ID_RE = re.compile(r'^[A-Za-z0-9\-_]{8,20}$')

# FIX 3: MIME real com python-magic (fallback seguro se não instalado)
try:
    import magic
    HAS_MAGIC = True
except ImportError:
    HAS_MAGIC = False

# Tipos MIME perigosos que nunca devem ser servidos como inline
DANGEROUS_MIMES = {
    "application/x-executable", "application/x-dosexec",
    "application/x-msdownload", "application/x-msdos-program",
    "text/x-shellscript", "application/x-sh",
    "application/x-php", "text/x-php",
    "application/x-python", "text/x-python",
    "application/x-perl",
}

BLOCKED_EXTENSIONS = {
    ".exe", ".bat", ".cmd", ".com", ".scr", ".vbs", ".jse",
    ".wsf", ".wsh", ".msi", ".msp", ".ps1", ".sh", ".bash",
    ".php", ".py", ".rb", ".pl", ".cgi", ".asp", ".aspx",
}

def validate_file_id(fid: str) -> bool:
    return bool(VALID_ID_RE.match(fid))

def generate_id() -> str:
    return secrets.token_urlsafe(12)

def human_size(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"

def sanitize_filename(name: str) -> str:
    name = secure_filename(name)
    name = re.sub(r'[^\w.\-]', '_', name)
    return name[:255]

def ip_key(req) -> str:
    ip = req.headers.get("X-Forwarded-For", req.remote_addr or "")
    ip = ip.split(",")[0].strip()
    return hashlib.sha256(ip.encode()).hexdigest()[:24]

# ─────────────────────────────────────────────────────────────
# FIX 4: Limite de uploads por IP
# ─────────────────────────────────────────────────────────────
def count_uploads_by_ip(ik: str) -> int:
    count = 0
    for mf in META_FOLDER.glob("*.json"):
        try:
            meta = json.loads(mf.read_text())
            if meta.get("uploader") == ik and time.time() < meta["expires_at"]:
                count += 1
        except Exception:
            pass
    return count

def get_total_disk_usage() -> int:
    return sum(f.stat().st_size for f in UPLOAD_FOLDER.iterdir() if f.is_file())

# ─────────────────────────────────────────────────────────────
# META
# ─────────────────────────────────────────────────────────────
def save_meta(file_id, name, size, uploader):
    meta = {
        "id": file_id,
        "name": name,
        "size": size,
        "uploaded_at": time.time(),
        "expires_at": time.time() + EXPIRY_HOURS * 3600,
        "uploader": uploader,
        "downloads": 0,
    }
    (META_FOLDER / f"{file_id}.json").write_text(json.dumps(meta))
    return meta

def load_meta(file_id):
    if not validate_file_id(file_id):
        return None
    p = META_FOLDER / f"{file_id}.json"
    if not p.exists():
        return None
    try:
        return json.loads(p.read_text())
    except Exception:
        return None

def delete_file(file_id):
    (UPLOAD_FOLDER / file_id).unlink(missing_ok=True)
    (META_FOLDER / f"{file_id}.json").unlink(missing_ok=True)

# ─────────────────────────────────────────────────────────────
# FIX 2: Lockout persistente em disco
# ─────────────────────────────────────────────────────────────
def get_lock(ik: str) -> dict:
    p = LOCK_FOLDER / f"{ik}.json"
    if not p.exists():
        return {"attempts": 0, "locked_until": 0}
    try:
        return json.loads(p.read_text())
    except Exception:
        return {"attempts": 0, "locked_until": 0}

def save_lock(ik: str, state: dict):
    (LOCK_FOLDER / f"{ik}.json").write_text(json.dumps(state))

def clear_lock(ik: str):
    (LOCK_FOLDER / f"{ik}.json").unlink(missing_ok=True)

# ─────────────────────────────────────────────────────────────
# FIX 5: Cleanup automático em background (sem depender de cron)
# ─────────────────────────────────────────────────────────────
def cleanup_loop():
    while True:
        try:
            for mf in list(META_FOLDER.glob("*.json")):
                try:
                    meta = json.loads(mf.read_text())
                    if time.time() > meta["expires_at"]:
                        delete_file(meta["id"])
                except Exception:
                    pass
        except Exception:
            pass
        time.sleep(15 * 60)   # roda a cada 15 minutos

threading.Thread(target=cleanup_loop, daemon=True).start()

# ─────────────────────────────────────────────────────────────
# AUTH TOTP + JWT
# ─────────────────────────────────────────────────────────────
totp = pyotp.TOTP(TOTP_SECRET)

def issue_token():
    return jwt.encode({
        "sub": "owner",
        "iat": int(time.time()),
        "exp": int(time.time()) + SESSION_SECS,
        "jti": secrets.token_hex(8),
    }, JWT_SECRET, algorithm="HS256")

def verify_token(token):
    try:
        jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        return True
    except Exception:
        return False

def require_auth(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        token = request.cookies.get("drop_session")
        if not token or not verify_token(token):
            return redirect("/login")
        return f(*args, **kwargs)
    return wrapper

# ─────────────────────────────────────────────────────────────
# ROTAS — AUTH
# ─────────────────────────────────────────────────────────────
@app.route("/login")
def login_page():
    return render_template("login.html", session_days=SESSION_DAYS)

@app.route("/auth", methods=["POST"])
@limiter.limit("10 per 5 minutes")
def auth():
    ik  = ip_key(request)
    now = time.time()

    # FIX 2: verifica lockout do disco
    state = get_lock(ik)
    if state["locked_until"] > now:
        remaining = int(state["locked_until"] - now)
        return jsonify({"error": f"Tente em {remaining // 60}m {remaining % 60}s."}), 429

    data = request.get_json(silent=True) or {}
    code = str(data.get("code", "")).strip()

    if not code or len(code) != 6 or not code.isdigit():
        return jsonify({"error": "Código inválido."}), 400

    if totp.verify(code, valid_window=1):
        clear_lock(ik)
        token = issue_token()
        resp = make_response(jsonify({"ok": True}))
        resp.set_cookie("drop_session", token,
                        httponly=True, secure=True,
                        samesite="Strict", max_age=SESSION_SECS)
        return resp

    # Falha — incrementa lockout
    state["attempts"] = state.get("attempts", 0) + 1
    if state["attempts"] >= MAX_ATTEMPTS:
        state["locked_until"] = now + LOCKOUT_SECONDS
        state["attempts"] = 0
        save_lock(ik, state)
        return jsonify({"error": f"Bloqueado por {LOCKOUT_SECONDS // 60} minutos."}), 429
    save_lock(ik, state)
    return jsonify({"error": f"Código incorreto. {MAX_ATTEMPTS - state['attempts']} tentativa(s)."}), 401

@app.route("/logout", methods=["POST"])
def logout():
    resp = make_response(redirect("/login"))
    resp.delete_cookie("drop_session", secure=True, samesite="Strict")
    return resp

# ─────────────────────────────────────────────────────────────
# ROTAS — PRINCIPAIS
# ─────────────────────────────────────────────────────────────
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
    ext = Path(original_name).suffix.lower()
    if ext in BLOCKED_EXTENSIONS:
        return jsonify({"error": "Tipo de arquivo não permitido."}), 400

    ik = ip_key(request)

    # FIX 4: limite de arquivos por IP
    if count_uploads_by_ip(ik) >= MAX_UPLOADS_PER_IP:
        return jsonify({"error": f"Limite de {MAX_UPLOADS_PER_IP} arquivos ativos por IP."}), 429

    # FIX 4: limite de disco total
    if get_total_disk_usage() > MAX_DISK_USAGE:
        return jsonify({"error": "Servidor sem espaço disponível."}), 507

    file_id = generate_id()
    dest    = UPLOAD_FOLDER / file_id

    try:
        f.save(dest)
    except Exception:
        dest.unlink(missing_ok=True)
        return jsonify({"error": "Erro ao salvar."}), 500

    size = dest.stat().st_size
    if size == 0 or size > MAX_SIZE:
        dest.unlink(missing_ok=True)
        return jsonify({"error": "Arquivo inválido ou muito grande."}), 400

    # FIX 3: verificação real de MIME com python-magic
    if HAS_MAGIC:
        real_mime = magic.from_file(str(dest), mime=True)
        if real_mime in DANGEROUS_MIMES:
            dest.unlink(missing_ok=True)
            return jsonify({"error": "Tipo de arquivo não permitido."}), 400

    meta = save_meta(file_id, original_name, size, ik)
    return jsonify({
        "id":   file_id,
        "link": f"/d/{file_id}",
        "size": human_size(size),
        "name": original_name,
    })

@app.route("/d/<file_id>")
def download_page(file_id):
    meta = load_meta(file_id)
    if not meta:
        abort(404)
    if time.time() > meta["expires_at"]:
        delete_file(file_id)
        abort(410)

    remaining  = int(meta["expires_at"] - time.time())
    h, m       = divmod(remaining, 3600)
    expire_pct = max(0, min(100, (remaining / (EXPIRY_HOURS * 3600)) * 100))

    ext = Path(meta["name"]).suffix.lower()
    icons = {
        ".pdf": "📄", ".zip": "🗜️", ".rar": "🗜️", ".7z": "🗜️",
        ".mp4": "🎬", ".mkv": "🎬", ".avi": "🎬", ".mov": "🎬",
        ".mp3": "🎵", ".wav": "🎵", ".flac": "🎵",
        ".jpg": "🖼️", ".jpeg": "🖼️", ".png": "🖼️", ".gif": "🖼️",
        ".doc": "📝", ".docx": "📝", ".txt": "📝",
        ".xls": "📊", ".xlsx": "📊", ".ppt": "📊", ".pptx": "📊",
        ".iso": "💿",
    }

    return render_template("download.html",
        file_id    = file_id,
        name       = meta["name"],
        size       = human_size(meta["size"]),
        downloads  = meta["downloads"],
        expires_in = f"{h}h {m // 60}m",
        expire_pct = round(expire_pct, 1),
        icon       = icons.get(ext, "📦"),
    )

@app.route("/download/<file_id>")
def download_file(file_id):
    meta = load_meta(file_id)
    if not meta:
        abort(404)
    if time.time() > meta["expires_at"]:
        delete_file(file_id)
        abort(410)

    fp = UPLOAD_FOLDER / file_id
    if not fp.exists():
        abort(404)

    # Garante que não saiu da pasta (path traversal)
    try:
        fp.resolve().relative_to(UPLOAD_FOLDER.resolve())
    except ValueError:
        abort(403)

    meta["downloads"] += 1
    (META_FOLDER / f"{file_id}.json").write_text(json.dumps(meta))

    mime = mimetypes.guess_type(meta["name"])[0] or "application/octet-stream"
    resp = make_response(send_file(fp, mimetype=mime,
                                   as_attachment=True,
                                   download_name=meta["name"]))
    resp.headers["X-Content-Type-Options"] = "nosniff"
    return resp

# ─────────────────────────────────────────────────────────────
# ERROR HANDLERS
# ─────────────────────────────────────────────────────────────
@app.errorhandler(404)
def not_found(e):
    return jsonify({"error": "Não encontrado."}), 404

@app.errorhandler(410)
def gone(e):
    return render_template("expired.html"), 410

@app.errorhandler(413)
def too_large(e):
    return jsonify({"error": "Arquivo muito grande. Limite: 4 GB."}), 413

@app.errorhandler(429)
def rate_limit(e):
    return jsonify({"error": "Muitas requisições."}), 429

@app.errorhandler(500)
def server_error(e):
    return jsonify({"error": "Erro interno."}), 500
