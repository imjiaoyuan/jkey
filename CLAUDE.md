# CLAUDE.md

This file provides guidance to Claude Code when working with code in this repository.

## Project Overview

**jkey** — Python library for password management and TOTP verification. Manages TOTP secrets, website passwords, generates random passwords, and exports plaintext data. All data is encrypted with AES-256-CBC + HMAC and stored in `~/.config/jkey/`, each type in its own file.

## Commands

### 2FA
- `uv run jkey 2fa ls [keyword]` — List accounts and current TOTP codes (case-insensitive filter)
- `uv run jkey 2fa add <image_path>` — Import account from QR code image (auto-saves image encrypted)
- `uv run jkey 2fa rm <account>` — Remove an account

### Recovery Codes
- `uv run jkey rc add <file>` — Import recovery codes from file (filename as account name)
- `uv run jkey rc ls [keyword]` — List recovery codes
- `uv run jkey rc rm <account>` — Remove recovery codes

### Password Management
- `uv run jkey pm ls [keyword]` — List/filter stored passwords
- `uv run jkey pm get [-L N] [--no-upper] [--no-lower] [--no-digits] [--no-symbols]` — Generate random password
- `uv run jkey pm add <name>` — Store a password (interactive input)
- `uv run jkey pm rm <name>` — Delete a password

### Vault
- `uv run jkey pv init` — Initialize vault (set master password)
- `uv run jkey pv unlock` — Unlock vault
- `uv run jkey pv lock` — Lock vault
- `uv run jkey pv set-pw` — Change master password
- `uv run jkey pv encrypt <file> [-o output.jkey]` — Encrypt a file
- `uv run jkey pv decrypt <file.jkey> [-o output]` — Decrypt a .jkey file
- `uv run jkey pv export totp [-o file.json]` — Export TOTP secrets (JSON, re-verifies master password)
- `uv run jkey pv export passwords [-o file.csv]` — Export passwords (CSV)
- `uv run jkey pv export recovery [-o file.txt]` — Export recovery codes (TXT)
- `uv run jkey pv export qr -o <dir>` — Export QR code images
- `uv run jkey pv export all -o <dir>` — Export everything

### Environment
- `JKEY_PASS` — Set master password via env var to skip interactive prompt

## Project Structure

```
src/
└── jkey/
    ├── __init__.py
    ├── __main__.py              # python -m jkey entry
    ├── cli.py                   # argparse CLI entry
    ├── aes.py                   # AES-256-CBC + HMAC pure Python
    ├── 2fa/
    │   ├── core.py              # TOTP algorithm
    │   ├── add.py               # QR code scanning and import
    │   ├── ls.py                # List accounts and TOTP codes
    │   └── rm.py                # Remove account
    ├── rc/
    │   ├── add.py               # Import recovery codes
    │   ├── ls.py                # List recovery codes
    │   └── rm.py                # Remove recovery codes
    ├── pm/
    │   ├── core.py              # Password data access
    │   ├── add.py               # Store password
    │   ├── get.py               # Generate random password
    │   ├── ls.py                # List passwords
    │   └── rm.py                # Delete password
    └── pv/
        ├── core.py              # Vault core (init, lock, session, crypto I/O)
        ├── init.py              # Vault initialization
        ├── unlock.py            # Vault unlock
        ├── lock.py              # Vault lock
        ├── set_pw.py            # Change master password
        ├── encrypt.py           # Encrypt a file
        ├── decrypt.py           # Decrypt a .jkey file
        └── export.py            # Data export
tests/
├── test_aes.py
├── test_totp.py
└── test_generator.py
.github/
└── workflows/
    ├── ci.yml                   # CI: ruff lint + pytest
    └── publish.yml              # PyPI publish (tag + manual trigger)
```

## Architecture

- **Encryption**: AES-256-CBC + HMAC-SHA256. Version 3 format uses separate encryption and auth keys. Files stored in `~/.config/jkey/` (`totp.jkey`, `passwords.jkey`, `recovery.jkey`), each independently encrypted.
- **QR images**: `jkey 2fa add` auto-saves QR images encrypted to `~/.config/jkey/qr/<name>.jkey`.
- **Session**: Master password is cached in `~/.config/jkey/.session` (local only, permission 600) with a 5-minute timeout across processes. `export` commands re-verify the password.
- **Backup**: Copy `~/.config/jkey/` to migrate to another machine.
- **Password generation**: Uses Python `secrets` module (CSPRNG), supports custom length and character sets.
- **Dependencies**: Only `opencv-python-headless` (QR scanning).
- **Package management**: `uv` + `pyproject.toml`. Python >=3.10.
- **Testing**: `pytest` + `ruff` lint, runs automatically in CI.

## Data files

```
~/.config/jkey/
├── .session           # Session cache (5 min timeout)
├── totp.jkey          # Encrypted TOTP secrets
├── passwords.jkey     # Encrypted passwords
├── recovery.jkey      # Encrypted recovery codes
└── qr/
    └── <account>.jkey # Encrypted QR images
```

`.gitignore` excludes `.venv`, `.python-version`, `__pycache__`, `*.pyc`, `*.tmp`, `.ruff_cache/`, `*.egg-info/`, `dist/`.
