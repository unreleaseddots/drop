# Drop

Drop é uma aplicação web para upload temporário de arquivos com expiração automática. O objetivo do projeto é permitir o envio de arquivos, geração de links únicos para download e remoção automática após determinado tempo, mantendo a aplicação simples, organizada e adequada para execução em VPS Linux.

## Funcionalidades

- Upload de arquivos
- Geração de link único para download
- Expiração automática de arquivos
- Script de limpeza (cleanup)
- Interface web com páginas HTML
- Estrutura preparada para execução em servidor Linux

## Stack Utilizada

- Python 3.11+
- Flask
- HTML5
- Execução em VPS Linux

## Estrutura do Projeto


.
├── app.py
├── cleanup.py
├── requirements.txt
├── templates/
└── uploads/ # diretório de runtime (não deve ser versionado)


## Instalação

Clone o repositório:

```bash
git clone git@github.com:unreleaseddots/drop.git
cd drop

Crie e ative um ambiente virtual:

python -m venv venv
source venv/bin/activate

Instale as dependências:

pip install -r requirements.txt
Execução
python app.py

A aplicação ficará disponível em:

http://127.0.0.1:5000
Boas Práticas

Não versionar arquivos sensíveis (.env, tokens, credenciais)

Não versionar arquivos de runtime (uploads, locks, cache)

Utilizar variáveis de ambiente para configurações sensíveis

Separar ambiente de desenvolvimento e produção

Deploy em Produção

Para ambiente de produção em VPS Linux, recomenda-se:

Gunicorn como servidor WSGI

Nginx como proxy reverso

Systemd para gerenciamento do serviço

HTTPS com Certbot

Exemplo de execução com Gunicorn:

gunicorn -w 4 -b 0.0.0.0:8000 app:app
Melhorias Futuras

Limite de tamanho de upload

Rate limiting

Hash de integridade de arquivos

Dockerização

Logs estruturados

Testes automatizados

Projeto desenvolvido para estudo, prática de backend em Python e organização de aplicação web para ambiente real.
