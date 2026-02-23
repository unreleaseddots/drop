#!/usr/bin/env python3
"""
setup.py — gera os segredos do DROP e configura o ambiente.
Execute UMA VEZ no servidor após instalar as dependências.

Uso:
    python3 setup.py
"""
import os
import sys
import secrets
from pathlib import Path

try:
    import pyotp
except ImportError:
    os.system(f"{sys.executable} -m pip install pyotp --break-system-packages -q")
    import pyotp

totp_secret = pyotp.random_base32(length=32)
jwt_secret  = secrets.token_hex(48)
cleanup_tok = secrets.token_hex(32)

SEP = "═" * 60

print(f"""
╔{SEP}╗
║  DROP — Geração de segredos                                ║
╠{SEP}╣

  ┌─ TOTP_SECRET ──────────────────────────────────────────┐
  │  {totp_secret}  │
  └────────────────────────────────────────────────────────┘
  → Cole no generator.py (seu PC) e no filehost.service

  ┌─ JWT_SECRET ───────────────────────────────────────────┐
  │  {jwt_secret[:56]}  │
  │  {jwt_secret[56:]}  │
  └────────────────────────────────────────────────────────┘

  ┌─ CLEANUP_TOKEN ────────────────────────────────────────┐
  │  {cleanup_tok}  │
  └────────────────────────────────────────────────────────┘

  Cole este bloco no filehost.service (seção [Service]):

  Environment="TOTP_SECRET={totp_secret}"
  Environment="JWT_SECRET={jwt_secret}"
  Environment="CLEANUP_TOKEN={cleanup_tok}"

╚{SEP}╝
""")
