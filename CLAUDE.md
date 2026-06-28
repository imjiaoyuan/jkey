# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**jkey** — Python CLI tool and library for password management and TOTP verification. Manages TOTP secrets, website passwords, recovery codes; generates random passwords; and exports plaintext data. All data is encrypted with AES-256-CBC + HMAC-SHA256 and stored in `~/.config/jkey/`, each type in its own file. Pure Python — no OpenSSL or libsodium needed.

## Commands

### Development
- `uv sync --group dev` — Install all dependencies including dev tools
- `uv run pytest tests/` — Run all tests with coverage
- `uv run pytest tests/ -k "test_name"` — Run a single test by name pattern
- `uv run ruff check src/ tests/` — Lint
- `uv build` — Build distribution packages

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
- `JKEY_PASS` — Set master password via env var to skip interactive prompt. Export commands still re-verify the password even when `JKEY_PASS` is set.

## Project Structure

```
src/
└── jkey/
    ├── __init__.py
    ├── __main__.py              # python -m jkey entry
    ├── cli.py                   # argparse CLI entry (lazy imports)
    ├── aes.py                   # AES-256-CBC + HMAC pure Python implementation
    ├── 2fa/
    │   ├── core.py              # TOTP algorithm (RFC 6238)
    │   ├── add.py               # QR code scanning (opencv) and import
    │   ├── ls.py                # List accounts and TOTP codes
    │   └── rm.py                # Remove account
    ├── rc/
    │   ├── add.py               # Import recovery codes
    │   ├── ls.py                # List recovery codes
    │   └── rm.py                # Remove recovery codes
    ├── pm/
    │   ├── core.py              # Password data access (re-exports from pv.core)
    │   ├── add.py               # Store password
    │   ├── get.py               # Generate random password (secrets module)
    │   ├── ls.py                # List passwords
    │   └── rm.py                # Delete password
    └── pv/
        ├── core.py              # Vault core — session, file I/O, locking, QR storage
        ├── init.py              # Vault initialization
        ├── unlock.py            # Vault unlock
        ├── lock.py              # Vault lock
        ├── set_pw.py            # Change master password
        ├── encrypt.py           # Encrypt arbitrary file
        ├── decrypt.py           # Decrypt a .jkey file
        └── export.py            # Data export (re-verifies password)
tests/
├── test_aes.py                  # Encrypt/decrypt roundtrip, v2 compat, tamper resistance
├── test_totp.py                 # RFC 4226 test vectors, base32, TOTP generation
└── test_generator.py            # Password generation: charset, length, uniqueness
.github/
└── workflows/
    ├── ci.yml                   # CI: ruff lint + pytest (py3.10–3.14)
    └── publish.yml              # PyPI publish (tag + manual trigger)
```

## Architecture

### Layered Design

```
CLI (cli.py) → Domain modules (2fa/ pm/ rc/) → Vault core (pv/core.py) → Crypto (aes.py)
```

- **`aes.py`** — Pure-Python AES-256-CBC + HMAC-SHA256. Has zero external dependencies. Exposes only `encrypt(dict, password) → dict` and `decrypt(dict, password) → dict | None`. All internal functions (`_key_expansion`, `_encrypt_block`, `_pkcs7_pad`, etc.) are private. PBKDF2-HMAC-SHA256 with 600,000 iterations.
- **`pv/core.py`** — Vault session manager and the sole data-access layer. Module-level globals (`_session_password`, `_totp_cache`, `_passwords_cache`, `_recovery_cache`) track unlocked state. All domain modules read/write through its `load_*`/`save_*` functions. Also manages QR image storage.
- **Domain modules** (`2fa/`, `pm/`, `rc/`) — Each implements CLI command handlers. They import from `pv.core` for data access; never touch `aes.py` directly.
- **`cli.py`** — argparse entry point. Uses `importlib.import_module()` for **lazy imports**: each subcommand's module is only imported when that subcommand is invoked. This avoids loading `opencv-python-headless` (heavy) when the user only needs `pm ls` or `pv unlock`.

### Encryption Format

Data files (`.jkey`) are JSON objects with base64-encoded fields. Version history:

| Version | PBKDF2 Output | Enc Key | MAC Key |
|---------|--------------|---------|---------|
| 1–2 | 32 bytes | bytes 0–32 | same as enc key |
| 3 (current) | 64 bytes | bytes 0–32 | bytes 32–64 |

`aes.decrypt()` handles all versions transparently. `aes.encrypt()` always produces v3. The `mac` covers `iv + ciphertext` (encrypt-then-MAC). Tampered ciphertext or MAC returns `None`.

### Session Management

- On unlock, the master password is cached in memory (`_session_password`) and persisted to `~/.config/jkey/.session` (mode 600) with a 5-minute TTL.
- The `.session` file is itself encrypted: session version `sv=2` encrypts the session blob with the password; older `sv=1` used a SHA-256 hash of the password as the encryption key.
- On next use, `_load_session()` is tried first (fast path). If it fails or expired, falls back to `_unlock_all()` which re-decrypts vault files.
- Failed password attempts use exponential backoff (2^attempt seconds), max 3 attempts.
- `JKEY_PASS` env var is checked first; if wrong, falls through to interactive prompt.
- Export commands re-verify the master password via `getpass` even when unlocked, as a safety measure. `JKEY_PASS` satisfies this re-verification.

### File I/O (Atomic Writes)

`_write_jkey()` writes to a `.tmp` file then uses `os.replace()` (atomic on POSIX). Stale `.tmp` files from crashed writes are silently removed on next write. Files are created with mode 600.

### Password Generation

`pm/get.py` uses Python's `secrets` module (CSPRNG). Character sets: lowercase, uppercase, digits, and `!@#$%^&*`. At least one character set must be enabled; length must be ≥ the number of enabled sets (one guaranteed char per set). Raises `ValueError` on invalid config.

## Testing

- Tests access private functions via `importlib.import_module("jkey.2fa.core")._hotp` — the same lazy-import pattern used by the CLI.
- `test_aes.py::TestV2Compat` manually constructs v2-format ciphertexts to verify backward compatibility.
- TOTP tests include RFC 4226 test vectors (counter 0–9) against known HOTP values.
- Coverage configured in `pyproject.toml` (`[tool.coverage.run]` / `[tool.coverage.report]`).

## Data files

```
~/.config/jkey/
├── .session           # Encrypted session cache (5 min timeout, mode 600)
├── totp.jkey          # Encrypted TOTP secrets: {name: base32_secret}
├── passwords.jkey     # Encrypted passwords: {name: password}
├── recovery.jkey      # Encrypted recovery codes: {account: [code, ...]}
└── qr/
    └── <name>.jkey    # Encrypted QR images (JPEG bytes base64-encoded)
```

`.gitignore` excludes `.venv`, `.python-version`, `__pycache__`, `*.pyc`, `*.tmp`, `.ruff_cache/`, `*.egg-info/`, `dist/`.
