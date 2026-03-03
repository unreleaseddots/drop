# DROP — v4.1 FINAL
# Admin protegido por senha separada

import os
import json
import time
import hashlib
import secrets
import mimetypes
import re
import threading
from pathlib import Path
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
UPLOAD_FOLDER    = Path(os.environ.get("UPLOAD_FOLDER", "/opt/filehost/uploads"))
META_FOLDER      = Path(os.environ.get("META_FOLDER",   "/opt/filehost/meta"))
LOCK_FOLDER      = Path(os.environ.get("LOCK_FOLDER",   "/opt/filehost/locks"))

MAX_SIZE             = 4 * 1024 * 1024 * 1024
MAX_DISK_USAGE       = 100 * 1024 * 1024 * 1024
MAX_UPLOADS_PER_IP   = 50
MAX_ATTEMPTS         = 5
LOCKOUT_SECONDS      = 15 * 60
SESSION_DAYS         = int(os.environ.get("SESSION_DAYS", "7"))
SESSION_SECS         = SESSION_DAYS * 86400

EXPIRY_OPTIONS = {
    "1h":  1,
    "6h":  6,
    "12h": 12,
    "24h": 24,
}
DEFAULT_EXPIRY = "24h"

TOTP_SECRET    = os.environ["TOTP_SECRET"]
JWT_SECRET     = os.environ["JWT_SECRET"]
API_TOKEN      = os.environ.get("API_TOKEN", secrets.token_hex(32))
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "")

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = MAX_SIZE

for folder in (UPLOAD_FOLDER, META_FOLDER, LOCK_FOLDER):
    folder.mkdir(parents=True, exist_ok=True)

# ─────────────────────────────────────────────────────────────
# RATE LIMIT
# ─────────────────────────────────────────────────────────────
limiter = Limiter(get_remote_address, app=app,
                  default_limits=["500/day", "100/hour"],
                  storage_uri="memory://")

# ─────────────────────────────────────────────────────────────
# HEADERS DE SEGURANÇA
# ─────────────────────────────────────────────────────────────
@app.before_request
def generate_nonce():
    request._csp_nonce = secrets.token_urlsafe(16)

@app.context_processor
def inject_globals():
    return {
        "csp_nonce": getattr(request, "_csp_nonce", ""),
        "expiry_options": EXPIRY_OPTIONS,
    }

@app.after_request
def security_headers(response):
    nonce = getattr(request, "_csp_nonce", "")
    response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains; preload"
    response.headers["X-Content-Type-Options"]    = "nosniff"
    response.headers["X-Frame-Options"]           = "DENY"
    response.headers["Referrer-Policy"]           = "no-referrer"
    response.headers["Permissions-Policy"]        = "geolocation=(), camera=(), microphone=()"
    response.headers["Content-Security-Policy"]   = (
        f"default-src 'self'; "
        f"script-src 'self' 'nonce-{nonce}'; "
        f"style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        f"font-src https://fonts.gstatic.com; "
        f"img-src 'self' data: blob:; "
        f"connect-src 'self'; "
        f"frame-ancestors 'none'; "
        f"form-action 'self';"
    )
    response.headers.pop("Server", None)
    return response

# ─────────────────────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────────────────────
VALID_ID_RE = re.compile(r'^[A-Za-z0-9\-_]{8,20}$')
IMAGE_EXTS  = {".jpg", ".jpeg", ".png", ".gif", ".webp", ".bmp"}
BLOCKED_EXTENSIONS = {
    ".exe", ".bat", ".cmd", ".com", ".scr", ".vbs", ".jse",
    ".wsf", ".wsh", ".msi", ".msp", ".ps1", ".sh", ".bash",
    ".php", ".py", ".rb", ".pl", ".cgi", ".asp", ".aspx",
}

try:
    import magic
    HAS_MAGIC = True
except ImportError:
    HAS_MAGIC = False

DANGEROUS_MIMES = {
    "application/x-executable", "application/x-dosexec",
    "application/x-msdownload", "text/x-shellscript",
    "application/x-php", "application/x-python",
}

def validate_file_id(fid):
    return bool(VALID_ID_RE.match(str(fid)))

def generate_id():
    return secrets.token_urlsafe(12)

def human_size(n):
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"

def sanitize_filename(name):
    name = secure_filename(name)
    name = re.sub(r'[^\w.\-]', '_', name)
    return name[:255]

def ip_key(req):
    ip = req.headers.get("X-Forwarded-For", req.remote_addr or "")
    return hashlib.sha256(ip.split(",")[0].strip().encode()).hexdigest()[:24]

def get_total_disk_usage():
    try:
        return sum(f.stat().st_size for f in UPLOAD_FOLDER.iterdir() if f.is_file())
    except Exception:
        return 0

def count_uploads_by_ip(ik):
    count = 0
    for mf in META_FOLDER.glob("*.json"):
        try:
            meta = json.loads(mf.read_text())
            if meta.get("uploader") == ik and time.time() < meta["expires_at"]:
                count += 1
        except Exception:
            pass
    return count

# ─────────────────────────────────────────────────────────────
# META
# ─────────────────────────────────────────────────────────────
def save_meta(file_id, name, size, uploader, expiry_hours, password_hash=None, is_image=False):
    meta = {
        "id":            file_id,
        "name":          name,
        "size":          size,
        "uploaded_at":   time.time(),
        "expires_at":    time.time() + expiry_hours * 3600,
        "expiry_hours":  expiry_hours,
        "uploader":      uploader,
        "downloads":     0,
        "password_hash": password_hash,
        "is_image":      is_image,
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

def list_all_files():
    files = []
    for mf in sorted(META_FOLDER.glob("*.json"), key=lambda x: x.stat().st_mtime, reverse=True):
        try:
            meta = json.loads(mf.read_text())
            meta["expired"]    = time.time() > meta["expires_at"]
            meta["size_human"] = human_size(meta["size"])
            remaining = int(meta["expires_at"] - time.time())
            if remaining > 0:
                h, r = divmod(remaining, 3600)
                meta["expires_in"] = f"{h}h {r // 60}m"
            else:
                meta["expires_in"] = "Expirado"
            files.append(meta)
        except Exception:
            pass
    return files

# ─────────────────────────────────────────────────────────────
# LOCKOUT PERSISTENTE
# ─────────────────────────────────────────────────────────────
def get_lock(ik):
    p = LOCK_FOLDER / f"{ik}.json"
    if not p.exists():
        return {"attempts": 0, "locked_until": 0}
    try:
        return json.loads(p.read_text())
    except Exception:
        return {"attempts": 0, "locked_until": 0}

def save_lock(ik, state):
    (LOCK_FOLDER / f"{ik}.json").write_text(json.dumps(state))

def clear_lock(ik):
    (LOCK_FOLDER / f"{ik}.json").unlink(missing_ok=True)

# ─────────────────────────────────────────────────────────────
# CLEANUP AUTOMÁTICO
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
        time.sleep(15 * 60)

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
# AUTH ADMIN — senha separada
# ─────────────────────────────────────────────────────────────
def is_admin(req):
    """Verifica se o cookie de admin é válido."""
    if not ADMIN_PASSWORD:
        return False
    cookie = req.cookies.get("admin_session", "")
    return bool(cookie) and secrets.compare_digest(cookie, ADMIN_PASSWORD)

def require_admin(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        # Precisa estar logado no TOTP primeiro
        token = request.cookies.get("drop_session")
        if not token or not verify_token(token):
            return redirect("/login")
        # Depois precisa da senha de admin
        if not is_admin(request):
            return render_template("admin_login.html")
        return f(*args, **kwargs)
    return wrapper

# API token auth
def require_api_token(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        token = request.headers.get("Authorization", "").replace("Bearer ", "").strip()
        if not token or not secrets.compare_digest(token, API_TOKEN):
            return jsonify({"error": "Token inválido."}), 401
        return f(*args, **kwargs)
    return wrapper

# ─────────────────────────────────────────────────────────────
# ROTAS — AUTH TOTP
# ─────────────────────────────────────────────────────────────
@app.route("/login")
def login_page():
    if verify_token(request.cookies.get("drop_session", "")):
        return redirect("/")
    return render_template("login.html", session_days=SESSION_DAYS)

@app.route("/auth", methods=["POST"])
@limiter.limit("10 per 5 minutes")
def auth():
    ik  = ip_key(request)
    now = time.time()
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
    resp.delete_cookie("admin_session", secure=True, samesite="Strict")
    return resp

# ─────────────────────────────────────────────────────────────
# ROTAS — AUTH ADMIN
# ─────────────────────────────────────────────────────────────
@app.route("/admin/auth", methods=["POST"])
@require_auth
@limiter.limit("10 per 5 minutes")
def admin_auth():
    data = request.get_json(silent=True) or {}
    pw   = str(data.get("password", "")).strip()

    if not ADMIN_PASSWORD:
        return jsonify({"error": "Admin não configurado."}), 500

    if not pw or not secrets.compare_digest(pw, ADMIN_PASSWORD):
        return jsonify({"error": "Senha incorreta."}), 401

    resp = make_response(jsonify({"ok": True}))
    resp.set_cookie("admin_session", ADMIN_PASSWORD,
                    httponly=True, secure=True,
                    samesite="Strict", max_age=SESSION_SECS)
    return resp

# ─────────────────────────────────────────────────────────────
# ROTAS — UPLOAD
# ─────────────────────────────────────────────────────────────
@app.route("/")
@require_auth
def index():
    return render_template("index.html")

def process_upload(file_obj, expiry_key, password, uploader_key):
    if not file_obj or not file_obj.filename:
        return None, "Arquivo inválido."

    name = sanitize_filename(file_obj.filename)
    ext  = Path(name).suffix.lower()

    if ext in BLOCKED_EXTENSIONS:
        return None, "Tipo de arquivo não permitido."

    expiry_hours = EXPIRY_OPTIONS.get(expiry_key, 24)

    if count_uploads_by_ip(uploader_key) >= MAX_UPLOADS_PER_IP:
        return None, f"Limite de {MAX_UPLOADS_PER_IP} arquivos ativos."

    if get_total_disk_usage() > MAX_DISK_USAGE:
        return None, "Servidor sem espaço."

    file_id = generate_id()
    dest    = UPLOAD_FOLDER / file_id

    try:
        file_obj.save(dest)
    except Exception:
        return None, "Erro ao salvar arquivo."

    size = dest.stat().st_size
    if size == 0 or size > MAX_SIZE:
        dest.unlink(missing_ok=True)
        return None, "Arquivo inválido ou muito grande."

    if HAS_MAGIC:
        import magic as _magic
        real_mime = _magic.from_file(str(dest), mime=True)
        if real_mime in DANGEROUS_MIMES:
            dest.unlink(missing_ok=True)
            return None, "Tipo de arquivo não permitido."

    password_hash = hashlib.sha256(password.encode()).hexdigest() if password else None
    is_image = ext in IMAGE_EXTS
    meta = save_meta(file_id, name, size, uploader_key, expiry_hours, password_hash, is_image)
    return meta, None

@app.route("/upload", methods=["POST"])
@require_auth
@limiter.limit("30 per hour")
def upload():
    files    = request.files.getlist("file")
    expiry   = request.form.get("expiry", DEFAULT_EXPIRY)
    password = request.form.get("password", "").strip()

    if not files or all(not f.filename for f in files):
        return jsonify({"error": "Nenhum arquivo enviado."}), 400

    ik      = ip_key(request)
    results = []
    errors  = []

    for f in files:
        if not f.filename:
            continue
        meta, err = process_upload(f, expiry, password, ik)
        if err:
            errors.append({"file": f.filename, "error": err})
        else:
            results.append({
                "id":       meta["id"],
                "link":     f"/d/{meta['id']}",
                "name":     meta["name"],
                "size":     human_size(meta["size"]),
                "expiry":   expiry,
                "password": bool(password),
            })

    return jsonify({"uploaded": results, "errors": errors})

# ─────────────────────────────────────────────────────────────
# ROTAS — DOWNLOAD
# ─────────────────────────────────────────────────────────────
@app.route("/d/<file_id>")
def download_page(file_id):
    meta = load_meta(file_id)
    if not meta:
        abort(404)
    if time.time() > meta["expires_at"]:
        delete_file(file_id)
        abort(410)

    remaining  = int(meta["expires_at"] - time.time())
    h, r       = divmod(remaining, 3600)
    expire_pct = max(0, min(100, remaining / (meta["expiry_hours"] * 3600) * 100))

    ext = Path(meta["name"]).suffix.lower()
    icons = {
        ".pdf": "📄", ".zip": "🗜️", ".rar": "🗜️", ".7z": "🗜️",
        ".mp4": "🎬", ".mkv": "🎬", ".avi": "🎬", ".mov": "🎬",
        ".mp3": "🎵", ".wav": "🎵", ".flac": "🎵",
        ".jpg": "🖼️", ".jpeg": "🖼️", ".png": "🖼️", ".gif": "🖼️", ".webp": "🖼️",
        ".doc": "📝", ".docx": "📝", ".txt": "📝",
        ".xls": "📊", ".xlsx": "📊", ".ppt": "📊", ".pptx": "📊",
        ".iso": "💿",
    }

    return render_template("download.html",
        file_id      = file_id,
        name         = meta["name"],
        size         = human_size(meta["size"]),
        downloads    = meta["downloads"],
        expires_in   = f"{h}h {r // 60}m",
        expire_pct   = round(expire_pct, 1),
        icon         = icons.get(ext, "📦"),
        is_image     = meta.get("is_image", False),
        has_password = bool(meta.get("password_hash")),
    )

@app.route("/download/<file_id>")
def download_file(file_id):
    meta = load_meta(file_id)
    if not meta:
        abort(404)
    if time.time() > meta["expires_at"]:
        delete_file(file_id)
        abort(410)

    if meta.get("password_hash"):
        password = request.args.get("p", "") or request.form.get("password", "")
        if not password:
            return jsonify({"error": "Senha necessária.", "need_password": True}), 403
        if hashlib.sha256(password.encode()).hexdigest() != meta["password_hash"]:
            return jsonify({"error": "Senha incorreta."}), 403

    fp = UPLOAD_FOLDER / file_id
    if not fp.exists():
        abort(404)

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

@app.route("/preview/<file_id>")
def preview(file_id):
    meta = load_meta(file_id)
    if not meta or not meta.get("is_image"):
        abort(404)
    if time.time() > meta["expires_at"]:
        abort(410)
    fp = UPLOAD_FOLDER / file_id
    if not fp.exists():
        abort(404)
    mime = mimetypes.guess_type(meta["name"])[0] or "image/jpeg"
    return send_file(fp, mimetype=mime)

# ─────────────────────────────────────────────────────────────
# ROTAS — ADMIN (senha separada)
# ─────────────────────────────────────────────────────────────
@app.route("/admin")
@require_admin
def admin():
    files      = list_all_files()
    active     = [f for f in files if not f["expired"]]
    expired    = [f for f in files if f["expired"]]
    return render_template("admin.html",
        files      = files,
        active     = active,
        expired    = expired,
        total_size = human_size(get_total_disk_usage()),
        api_token  = API_TOKEN,
    )

@app.route("/admin/delete/<file_id>", methods=["POST"])
@require_admin
def admin_delete(file_id):
    if not validate_file_id(file_id):
        return jsonify({"error": "ID inválido."}), 400
    delete_file(file_id)
    return jsonify({"ok": True})

@app.route("/admin/delete-expired", methods=["POST"])
@require_admin
def admin_delete_expired():
    removed = 0
    for mf in list(META_FOLDER.glob("*.json")):
        try:
            meta = json.loads(mf.read_text())
            if time.time() > meta["expires_at"]:
                delete_file(meta["id"])
                removed += 1
        except Exception:
            pass
    return jsonify({"ok": True, "removed": removed})

# ─────────────────────────────────────────────────────────────
# ROTAS — API
# ─────────────────────────────────────────────────────────────
@app.route("/api/upload", methods=["POST"])
@require_api_token
@limiter.limit("30 per hour")
def api_upload():
    files    = request.files.getlist("file")
    expiry   = request.form.get("expiry", DEFAULT_EXPIRY)
    password = request.form.get("password", "").strip()

    if not files or all(not f.filename for f in files):
        return jsonify({"error": "Nenhum arquivo enviado."}), 400

    ik      = ip_key(request)
    results = []
    errors  = []

    for f in files:
        if not f.filename:
            continue
        meta, err = process_upload(f, expiry, password, ik)
        if err:
            errors.append({"file": f.filename, "error": err})
        else:
            base = request.host_url.rstrip("/")
            results.append({
                "id":       meta["id"],
                "name":     meta["name"],
                "size":     human_size(meta["size"]),
                "link":     f"{base}/d/{meta['id']}",
                "download": f"{base}/download/{meta['id']}",
                "expiry":   expiry,
                "password": bool(password),
            })

    return jsonify({"uploaded": results, "errors": errors})

@app.route("/api/files")
@require_api_token
def api_files():
    files = [f for f in list_all_files() if not f["expired"]]
    return jsonify({"files": files, "count": len(files)})

@app.route("/api/delete/<file_id>", methods=["DELETE"])
@require_api_token
def api_delete(file_id):
    if not validate_file_id(file_id):
        return jsonify({"error": "ID inválido."}), 400
    if not load_meta(file_id):
        return jsonify({"error": "Não encontrado."}), 404
    delete_file(file_id)
    return jsonify({"ok": True})

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
