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
- `uv run jkey pm edit <name>` — Update an existing password (interactive input)
- `uv run jkey pm rm <name>` — Delete a password

### Vault
- `uv run jkey pv init` — Initialize vault (set master password)
- `uv run jkey pv unlock` — Unlock vault
- `uv run jkey pv lock` — Lock vault
- `uv run jkey pv status` — Show vault status (config directory, initialized/unlocked state)
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
- `JKEY_SESSION_TIMEOUT` — Session cache timeout in seconds (default: 300).

## Project Structure

```
src/
└── jkey/
    ├── __init__.py
    ├── __main__.py              # python -m jkey entry point (calls cli.main())
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
    │   ├── core.py              # Re-exports load_passwords/save_passwords from pv.core
    │   ├── add.py               # Store password
    │   ├── edit.py              # Update existing password
    │   ├── get.py               # Generate random password (secrets module)
    │   ├── ls.py                # List passwords
    │   └── rm.py                # Delete password
    └── pv/
        ├── core.py              # Vault core — session, file I/O, locking, QR storage
        ├── init.py              # Vault initialization
        ├── unlock.py            # Vault unlock
        ├── lock.py              # Vault lock
        ├── status.py            # Show vault status
        ├── set_pw.py            # Change master password
        ├── encrypt.py           # Encrypt arbitrary file
        ├── decrypt.py           # Decrypt a .jkey file
        └── export.py            # Data export (re-verifies password)
tests/
├── conftest.py                  # Shared fixtures: vault_dir, vault, mock_getpass
├── test_aes.py                  # Encrypt/decrypt roundtrip, v2 compat, tamper resistance
├── test_cli.py                  # CLI argument parsing and subcommand dispatch
├── test_generator.py            # Password generation: charset, length, uniqueness
├── test_list_and_export_paths.py # List/export function return value paths
├── test_operations.py           # CRUD operations: add, edit, remove across domains
├── test_totp.py                 # RFC 4226 test vectors, base32, TOTP generation
├── test_vault.py                # Vault core: session, lock, set-pw, init, encrypt/decrypt
└── test_vault_commands.py       # Vault CLI commands: init, unlock, lock, status, set-pw
.github/
└── workflows/
    ├── ci.yml                   # CI: ruff lint, pytest (py3.10–3.14), uv build
    └── publish.yml              # PyPI publish (tag + manual trigger)
```

## Architecture

### Layered Design

```
CLI (cli.py) → Domain modules (2fa/ pm/ rc/) → Vault core (pv/core.py) → Crypto (aes.py)
```

- **`aes.py`** — Pure-Python AES-256-CBC + HMAC-SHA256. Has zero external dependencies. Exposes only `encrypt(dict, password) → dict` and `decrypt(dict, password) → dict | None`. All internal functions (`_key_expansion`, `_encrypt_block`, `_pkcs7_pad`, etc.) are private. PBKDF2-HMAC-SHA256 with 600,000 iterations.
- **`pv/core.py`** — Vault session manager and the sole data-access layer. Module-level globals (`_session_password`, `_totp_cache`, `_passwords_cache`, `_recovery_cache`) track unlocked state. All domain modules read/write through its `load_*`/`save_*` functions. Also manages QR image storage. Uses `fcntl.flock` for concurrent access protection (shared locks for reads, exclusive for writes; no-op on Windows).
- **Domain modules** (`2fa/`, `pm/`, `rc/`) — Each implements CLI command handlers. They import from `pv.core` or their own `core.py` for data access; never touch `aes.py` directly. `pm/core.py` is a thin re-export layer: it re-exports `load_passwords` and `save_passwords` from `pv.core` so that `pm/` modules can import from their sibling `core.py` instead of reaching across to `pv.core` directly.
- **`cli.py`** — argparse entry point. Uses `importlib.import_module()` for **lazy imports**: each subcommand's module is only imported when that subcommand is invoked, keeping startup fast. All three `ls` subcommands (`2fa ls`, `pm ls`, `rc ls`) return structured data from their core functions; `cli.py` handles printing. Other commands print internally within their domain modules.

### Encryption Format

Data files (`.jkey`) are JSON objects with base64-encoded fields. Version history:

| Version | PBKDF2 Output | Enc Key | MAC Key |
|---------|--------------|---------|---------|
| 1–2 | 32 bytes | bytes 0–32 | same as enc key |
| 3 (current) | 64 bytes | bytes 0–32 | bytes 32–64 |

`aes.decrypt()` handles all versions transparently. `aes.encrypt()` always produces v3. The `mac` covers `iv + ciphertext` (encrypt-then-MAC). Tampered ciphertext or MAC returns `None`.

### Session Management

- On unlock, the master password and decrypted vault data are cached in memory (`_session_password`, `_totp_cache`, etc.) and persisted to `~/.config/jkey/.session` (mode 600) with a 5-minute TTL (configurable via `JKEY_SESSION_TIMEOUT` env var).
- Session format `sv=3`: plain JSON with `password`, `totp`, `passwords`, `recovery`, `expires` fields. Protected by filesystem permissions (mode 600), same threat model as the vault files. Older `sv=2`/`sv=1` formats (encrypted sessions) are rejected — user re-enters password once after upgrade.
- On next CLI invocation, `_load_session()` reads the session file directly without requiring the master password — like `sudo`'s timestamp mechanism. Timeout resets on each successful use (activity-based).
- If session is missing, expired, or old format: falls back to `_unlock_all()` which re-decrypts vault files and saves a new sv=3 session.
- Failed password attempts use exponential backoff (2^attempt seconds), max 3 attempts.
- `JKEY_PASS` env var is checked after session load fails; if wrong, falls through to interactive prompt.
- Export commands re-verify the master password via `getpass` even when unlocked, as a safety measure. `JKEY_PASS` satisfies this re-verification.

### File I/O (Atomic Writes)

`_write_jkey()` writes to a `.tmp` file then uses `os.replace()` (atomic on POSIX). Stale `.tmp` files from crashed writes are silently removed on next write. Files are created with mode 600. QR image filenames are sanitized by replacing invalid filesystem characters (`<>:"/\|?*`) with underscores.

### Password Generation

`pm/get.py` uses Python's `secrets` module (CSPRNG). Character sets: lowercase, uppercase, digits, and `!@#$%^&*()_+-=[]{}|;:,.<>?/`. At least one character set must be enabled; length must be ≥ the number of enabled sets (one guaranteed char per set). Raises `ValueError` on invalid config.

### Vault Initialization

`pv/init.py` checks password strength via `_check_password_strength()`: minimum 8 characters, recommends 12+ with 3 of 4 character classes (upper, lower, digit, special).

## Testing

### Fixtures (conftest.py)

- **`vault_dir`** — Creates a temp directory and monkeypatches all `pv.core` path constants (`CONFIG_DIR`, `TOTP_FILE`, etc.) to point there. Cleans up module-level cache globals after each test.
- **`vault`** — Returns an initialized-and-unlocked `pv.core` module scoped to the temp directory. Use for tests that need a ready vault.
- **`mock_getpass`** — Factory fixture that monkeypatches `getpass.getpass` to return a fixed password. Call as `mock_getpass(pw="custom-pw")` to set the password.

### Test patterns
- Tests access private functions via `importlib.import_module("jkey.2fa.core")._hotp` — the same lazy-import pattern used by the CLI.
- `test_aes.py::TestV2Compat` manually constructs v2-format ciphertexts to verify backward compatibility.
- TOTP tests include RFC 4226 test vectors (counter 0–9) against known HOTP values.
- Coverage configured in `pyproject.toml` (`[tool.coverage.run]` / `[tool.coverage.report]`).

## Data files

```
~/.config/jkey/
├── .session           # Session cache — plain JSON, mode 600 (5 min activity-based timeout)
├── .lock              # fcntl lock file (POSIX only)
├── totp.jkey          # Encrypted TOTP secrets: {name: base32_secret}
├── passwords.jkey     # Encrypted passwords: {name: password}
├── recovery.jkey      # Encrypted recovery codes: {account: [code, ...]}
└── qr/
    └── <name>.jkey    # Encrypted QR images (JPEG bytes base64-encoded)
```

On Windows, `CONFIG_DIR` falls back to `%APPDATA%/jkey` instead of `~/.config/jkey`.

`.gitignore` excludes `.venv`, `.python-version`, `__pycache__`, `*.pyc`, `*.tmp`, `.ruff_cache/`, `*.egg-info/`, `dist/`.
