# DROP 📦

> Upload anônimo de arquivos com autenticação TOTP e expiração automática em 24h.

![Python](https://img.shields.io/badge/Python-3.11+-blue?style=flat-square)
![Flask](https://img.shields.io/badge/Flask-3.0-black?style=flat-square)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)

---

## O que é

DROP é um serviço self-hosted de upload e compartilhamento de arquivos focado em privacidade:

- **Autenticação TOTP** — acesso por código de 6 dígitos que muda a cada 30 segundos
- **Links públicos** — quem receber o link pode baixar sem precisar de conta
- **Expiração automática** — arquivos deletados após 24 horas
- **Zero logs de IP** — nenhum dado pessoal armazenado
- **Limite de 4 GB** por arquivo

## Stack

- **Backend:** Python 3.11 + Flask + Gunicorn
- **Autenticação:** TOTP (RFC 6238) via pyotp + JWT para sessão
- **Servidor:** Nginx (reverse proxy) + systemd
- **Segurança:** CSP, CSRF token, HSTS, rate limiting, lockout persistente

---

## Instalação

### Requisitos
- VPS ou Raspberry Pi com Ubuntu/Debian
- Python 3.11+
- Nginx
- Domínio com HTTPS (certbot)

### 1. Clone o repositório

```bash
git clone https://github.com/SEU_USUARIO/drop.git
cd drop
```

### 2. Cria usuário e pastas

```bash
useradd --system --no-create-home --shell /usr/sbin/nologin filehost
mkdir -p /opt/filehost/{app,uploads,meta,locks,run}
cp -r . /opt/filehost/app/
chown -R filehost:filehost /opt/filehost
```

### 3. Instala dependências

```bash
python3 -m venv /opt/filehost/venv
/opt/filehost/venv/bin/pip install -r requirements.txt
```

### 4. Gera os segredos

```bash
cd /opt/filehost/app
python3 setup.py
```

Copie os valores gerados e cole no `filehost.service`.

### 5. Ativa o serviço

```bash
cp filehost.service /etc/systemd/system/
# edite o arquivo e cole os segredos gerados
nano /etc/systemd/system/filehost.service

systemctl daemon-reload
systemctl enable filehost
systemctl start filehost
```

### 6. Configura o Nginx

```bash
cp nginx.conf /etc/nginx/sites-available/upload
# edite e coloque seu domínio
nano /etc/nginx/sites-available/upload

ln -s /etc/nginx/sites-available/upload /etc/nginx/sites-enabled/
nginx -t && systemctl reload nginx
```

### 7. HTTPS

```bash
apt install certbot python3-certbot-nginx -y
certbot --nginx -d SEU_DOMINIO
```

### 8. Cron de limpeza

```bash
(crontab -u filehost -l 2>/dev/null; echo "*/15 * * * * /opt/filehost/venv/bin/python3 /opt/filehost/app/cleanup.py >> /var/log/filehost_cleanup.log 2>&1") | crontab -u filehost -
```

---

## Gerador de código (seu PC)

Instale e rode o `generator.py` no seu computador:

```bash
pip install pyotp
python3 generator.py
```

Cole o `TOTP_SECRET` gerado pelo `setup.py` na variável indicada no arquivo.

---

## Segurança

| Proteção | Implementação |
|---|---|
| Autenticação | TOTP (RFC 6238) — código de 30s |
| Brute force | Lockout após 5 tentativas, 15min de bloqueio persistente em disco |
| XSS | Content Security Policy estrita |
| CSRF | Token por sessão validado em todo POST |
| Clickjacking | X-Frame-Options: DENY + CSP frame-ancestors |
| Path traversal | Validação de ID por regex + resolve().relative_to() |
| MIME sniffing | X-Content-Type-Options: nosniff + force attachment |
| Fingerprinting | Headers Server e X-Powered-By removidos |
| Sessão | JWT assinado com HS256, cookie HttpOnly + Secure + SameSite=Strict |
| HTTPS | HSTS max-age=63072000, redirecionamento forçado |
| SQLi | Não aplicável — sem banco de dados |

---

## Estrutura

```
drop/
├── app.py              ← backend Flask
├── generator.py        ← gerador de código TOTP (rodar no PC)
├── setup.py            ← geração de segredos
├── cleanup.py          ← remoção de arquivos expirados (cron)
├── requirements.txt
├── filehost.service    ← serviço systemd
├── nginx.conf          ← configuração Nginx
└── templates/
    ├── index.html      ← página de upload
    ├── login.html      ← página de autenticação
    ├── download.html   ← página de download
    └── expired.html    ← página de arquivo expirado
```

---

## Licença

MIT — use, modifique e distribua à vontade.
