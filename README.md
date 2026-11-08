# 📬 Mailbox Provisioner

[![Python](https://img.shields.io/badge/python-3.9%2B-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](#license)

Bulk mailbox provisioning for self-hosted [Mailcow](https://mailcow.email/). Read users from a CSV file, create mailboxes through the Mailcow Admin API, and write the generated credentials to a protected output file.

> **Intended use:** administration of mail servers you own or are explicitly authorised to manage.

## Features

| Feature | What it does |
| --- | --- |
| **Idempotency** | Calls `GET /api/v1/get/mailbox/{email}` before `POST /api/v1/add/mailbox`, so existing mailboxes are skipped instead of duplicated. |
| **Rate limiting** | Enforces a configurable minimum delay between every GET and POST request. |
| **Dry run** | `--dry-run` performs zero network calls and prints the planned actions and generated passwords. |
| **Docker lab** | `docker-compose.lab.yml` binds Mailcow's ports to `127.0.0.1` and disables netfilter for isolated testing. |
| **Robust errors** | Handles HTTP failures and catches `JSONDecodeError`/HTML responses returned by WAFs. |
| **Safe output** | Refuses to write outside the working directory with `os.path.commonpath` and stores credentials with `0600` permissions. |

## Quick Start

### 1. Install

```bash
git clone https://github.com/trannguyenxuan27-ux/clone-mail.git
cd clone-mail
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### 2. Prepare a batch file

The first column is the local part (or a full address), and the second column is the display name:

```csv
alice,Alice Nguyen
bob,Bob Smith
```

A ready-to-use sample lives at `examples/users.csv`.

### 3. Preview with a dry run

```bash
python tool.py \
  --url https://mail.lab.local \
  --domain lab.local \
  --batch examples/users.csv \
  --dry-run
```

No network calls are made in this mode. Review the generated addresses and passwords before continuing.

### 4. Provision for real

```bash
export MAILCOW_API_KEY="your-mailcow-admin-api-key"

python tool.py \
  --url https://mail.lab.local \
  --domain lab.local \
  --batch examples/users.csv \
  --out credentials.csv
```

Credentials are written to `credentials.csv` with mode `0600`. The file is git-ignored by default.

### Options

| Flag | Description |
| --- | --- |
| `--url` | Mailcow base URL, for example `https://mail.lab.local`. |
| `--key` | Admin API key. Falls back to `MAILCOW_API_KEY`. Required unless `--dry-run` is used. |
| `--domain` | Target mail domain. |
| `--batch` | CSV file containing `local_part,name` rows. |
| `--out` | Credential CSV output path. Defaults to `credentials.csv`. |
| `--dry-run` | Print actions only, with no network calls. |
| `--quota` | Mailbox quota in MiB. Defaults to `1024`. |
| `--rate-limit` | Minimum seconds between API requests. Defaults to `0.25`. |
| `--timeout` | HTTP timeout in seconds. Defaults to `15`. |

## Docker Lab

Mailcow's lab override binds all service ports to loopback and disables the netfilter sidecar. It uses the `!override` YAML tag, so it requires Docker Compose v2.24 or newer:

```bash
docker compose -f docker-compose.yml -f docker-compose.lab.yml up -d
```

Exposed on `127.0.0.1` only:

| Port | Service |
| --- | --- |
| `80`, `443` | nginx (Mailcow UI and API) |
| `25`, `465`, `587` | postfix (SMTP) |
| `993`, `995` | dovecot (IMAP/POP3) |

`DISABLE_NETFILTER=1` stops the netfilter container from modifying host firewall rules. This override is intended for isolated labs and must never be exposed to the public internet.

## Ethical Note

This project is provided for **legitimate mail-server administration only**. Use it exclusively on infrastructure you own or have explicit written permission to manage. It must **not** be used to impersonate any organisation — including educational institutions — or to create deceptive, fraudulent, or abusive accounts. You are responsible for complying with applicable laws and your provider's acceptable-use policy.

Dự án này chỉ dành cho mục đích quản trị máy chủ email hợp pháp. Không được dùng để giả mạo bất kỳ tổ chức nào, bao gồm các tổ chức giáo dục, hoặc để tạo tài khoản lừa đảo.

## License

Released under the [MIT License](https://opensource.org/licenses/MIT).
