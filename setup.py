#!/usr/bin/env python3
"""
setup.py — gera os segredos do DROP e configura o ambiente.
Execute UMA VEZ no servidor (VPS) para inicializar.

Uso:
    python3 setup.py
"""
import os
import sys
import secrets

try:
    import pyotp
except ImportError:
    print("Instalando dependências...")
    os.system(f"{sys.executable} -m pip install pyotp qrcode pillow --break-system-packages -q")
    import pyotp

# ── Gera segredos ─────────────────────────────────────────────────────────────
totp_secret = pyotp.random_base32(length=32)   # 160 bits de entropia
jwt_secret  = secrets.token_hex(48)             # 384 bits
cleanup_tok = secrets.token_hex(32)             # 256 bits

# ── Exibe os valores ──────────────────────────────────────────────────────────
SEP = "═" * 62

print(f"""
╔{SEP}╗
║  DROP — Setup de segredos                                    ║
╠{SEP}╣

  ⚡ Segredos gerados com sucesso!

  ┌─ TOTP_SECRET ────────────────────────────────────────────┐
  │  {totp_secret:<56}  │
  └──────────────────────────────────────────────────────────┘
  → Cole este valor no generator.py (no seu PC)
  → E no arquivo /etc/systemd/system/filehost.service

  ┌─ JWT_SECRET ─────────────────────────────────────────────┐
  │  {jwt_secret[:56]}  │
  │  {jwt_secret[56:]}  │
  └──────────────────────────────────────────────────────────┘
  → Apenas no servidor (variável de ambiente)

  ┌─ CLEANUP_TOKEN ──────────────────────────────────────────┐
  │  {cleanup_tok:<56}  │
  └──────────────────────────────────────────────────────────┘
  → Apenas no servidor (variável de ambiente)

""")

# ── Gera o bloco de Environment para o .service ───────────────────────────────
env_block = f"""Environment="TOTP_SECRET={totp_secret}"
Environment="JWT_SECRET={jwt_secret}"
Environment="CLEANUP_TOKEN={cleanup_tok}"
"""

service_path = Path("/etc/systemd/system/filehost.service") if False else None

print("  ── Cole este bloco no filehost.service (seção [Service]) ──")
print()
for line in env_block.strip().splitlines():
    print(f"  {line}")
print()

# ── Tenta escrever direto no .service se existir ──────────────────────────────
from pathlib import Path
service_file = Path("/etc/systemd/system/filehost.service")

if service_file.exists():
    content = service_file.read_text()
    # Remove variáveis antigas se existirem
    lines = [l for l in content.splitlines()
             if not l.strip().startswith('Environment="TOTP_SECRET')
             and not l.strip().startswith('Environment="JWT_SECRET')
             and not l.strip().startswith('Environment="CLEANUP_TOKEN')]
    # Insere após a linha [Service]
    new_lines = []
    for line in lines:
        new_lines.append(line)
        if line.strip() == "[Service]":
            new_lines.extend(env_block.strip().splitlines())
    service_file.write_text("\n".join(new_lines))
    print("  ✅ Variáveis escritas automaticamente em filehost.service")
    print("     Execute: systemctl daemon-reload && systemctl restart filehost")
else:
    print("  ℹ️  filehost.service não encontrado — adicione as variáveis manualmente.")

print(f"""
╠{SEP}╣
║  PRÓXIMOS PASSOS:                                            ║
║                                                              ║
║  1. Copie o TOTP_SECRET para o generator.py no seu PC       ║
║  2. Reinicie o serviço: systemctl restart filehost           ║
║  3. Rode o generator.py e teste o login                      ║
╚{SEP}╝
""")
