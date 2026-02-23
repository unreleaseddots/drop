#!/usr/bin/env python3
"""
╔═══════════════════════════════════════════════════════════╗
║  DROP — Gerador de código TOTP                            ║
║  Rode este script no SEU PC para gerar o código de acesso ║
╚═══════════════════════════════════════════════════════════╝

Uso:
    python3 generator.py

Dependência (instale uma vez):
    pip install pyotp
"""

import sys
import time

try:
    import pyotp
except ImportError:
    print("❌ Instale o pyotp:  pip install pyotp")
    sys.exit(1)

# ══════════════════════════════════════════════════════════════════════════════
#  ⚠️  COLE AQUI O TOTP_SECRET GERADO PELO setup.py
#     Não compartilhe este arquivo com ninguém.
# ══════════════════════════════════════════════════════════════════════════════
TOTP_SECRET = "COLE_AQUI_O_SEU_TOTP_SECRET"
# ══════════════════════════════════════════════════════════════════════════════

def color(code, text):
    return f"\033[{code}m{text}\033[0m"

def main():
    if TOTP_SECRET == "COLE_AQUI_O_SEU_TOTP_SECRET":
        print(color("31;1", "\n⚠  ATENÇÃO: configure o TOTP_SECRET neste arquivo antes de usar!\n"))
        print("Execute o setup.py no servidor e cole o TOTP_SECRET aqui.")
        sys.exit(1)

    totp = pyotp.TOTP(TOTP_SECRET)

    print(color("33;1", "\n╔══════════════════════════════╗"))
    print(color("33;1",   "║  DROP — Gerador de acesso    ║"))
    print(color("33;1",   "╚══════════════════════════════╝"))
    print(color("90", "  Pressione Ctrl+C para sair\n"))

    last_code = None
    try:
        while True:
            now     = time.time()
            code    = totp.now()
            remaining = 30 - int(now) % 30

            # Barra de progresso visual
            filled  = int(remaining / 30 * 20)
            bar     = "█" * filled + "░" * (20 - filled)

            # Cor muda quando está perto do fim
            if remaining <= 5:
                code_color = "31;1"   # vermelho
                bar_color  = "31"
            elif remaining <= 10:
                code_color = "33;1"   # amarelo
                bar_color  = "33"
            else:
                code_color = "32;1"   # verde
                bar_color  = "32"

            if code != last_code:
                # Limpa e reimprime ao trocar o código
                print("\033[2J\033[H", end="")
                print(color("33;1", "╔══════════════════════════════╗"))
                print(color("33;1", "║  DROP — Gerador de acesso    ║"))
                print(color("33;1", "╚══════════════════════════════╝\n"))
                last_code = code

            # Linha do código
            print(f"\r  Código:  {color(code_color, code)}   [{color(bar_color, bar)}]  {remaining:2d}s  ", end="", flush=True)
            time.sleep(0.5)

    except KeyboardInterrupt:
        print(color("90", "\n\n  Gerador encerrado.\n"))

if __name__ == "__main__":
    main()
