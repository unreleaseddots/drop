#!/usr/bin/env python3
"""
cleanup.py — remove arquivos expirados.
Adicione ao cron:
  */15 * * * * /opt/filehost/venv/bin/python3 /opt/filehost/app/cleanup.py >> /var/log/filehost_cleanup.log 2>&1
"""
import json
import time
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
    print(f"[cleanup] {removed} arquivo(s) expirado(s) removido(s).")
