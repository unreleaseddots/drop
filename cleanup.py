cat > /root/filehost-auth/cleanup.py << 'EOF'
import json, time
from pathlib import Path

UPLOAD_FOLDER = Path("/opt/filehost/uploads")
META_FOLDER   = Path("/opt/filehost/meta")

removed = 0
for meta_file in META_FOLDER.glob("*.json"):
    try:
        meta = json.loads(meta_file.read_text())
        if time.time() > meta["expires_at"]:
            (UPLOAD_FOLDER / meta["id"]).unlink(missing_ok=True)
            meta_file.unlink(missing_ok=True)
            removed += 1
    except Exception as e:
        print(f"Erro em {meta_file.name}: {e}")

if removed:
    print(f"[cleanup] {removed} arquivo(s) removido(s).")
EOF
