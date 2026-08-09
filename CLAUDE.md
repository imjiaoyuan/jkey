# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**jkey** — Python CLI tool and library for password management and TOTP verification. Manages TOTP secrets, website passwords, recovery codes; generates random passwords; and exports plaintext data. All data is encrypted with AES-256-CBC + HMAC-SHA256 and stored in `~/.config/jkey/`, each type in its own file. Pure Python — no OpenSSL or libsodium needed. Cross-platform: Linux, macOS, and Windows. File locking via `portalocker`.

**Dependencies:** `portalocker` (required), `opencv-python-headless` (optional, only needed for `jkey 2fa add` QR scanning). Install with `pip install jkey[qr]` to include QR support. Build backend: `setuptools`.

## Commands

### Development
- `uv sync --group dev` — Install all dependencies including dev tools (`pytest>=8`, `pytest-cov>=6`, `ruff>=0.11`)
- `uv run pytest tests/` — Run all tests (coverage auto-configured via pyproject.toml)
- `uv run pytest tests/ -k "test_name"` — Run a single test by name pattern
- `uv run pytest tests/test_generator.py::TestGeneratePassword::test_default_length` — Run a specific test by path
- `uv run ruff check src/ tests/` — Lint (ruff config: `line-length=120`, `target-version=py310`, select `E,F,W,I`)
- `uv run ruff format src/ tests/` — Format
- `uv build` — Build distribution packages

CI (`.github/workflows/ci.yml`) runs lint on Python 3.13 (ubuntu only), tests on 3.10–3.14 across **ubuntu-latest, windows-latest, and macos-latest**, and `uv build` on every matrix OS. PyPI publishing (`.github/workflows/publish.yml`) triggers on `v*` tags and manual dispatch via trusted publishing (`id-token: write`).

### 2FA
- `uv run jkey 2fa ls [keyword]` — List accounts and current TOTP codes (case-insensitive filter)
- `uv run jkey 2fa add <image_path>` — Import account from QR code image (auto-saves image encrypted)
- `uv run jkey 2fa rm <account>` — Remove an account (also prompts to delete matching recovery codes)

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
- `uv run jkey pm import <file.csv> [-n] [-v] [--replace] [-d skip|overwrite|rename]` — Import passwords from browser CSV export

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

### Quick Start (end-to-end workflow)

```bash
# Initialize vault (set master password)
jkey pv init

# Add a 2FA account from QR code image
jkey 2fa add ./github.jpg

# List TOTP codes (optional keyword filter)
jkey 2fa ls
jkey 2fa ls github

# Generate a random password
jkey pm get -L 24

# Store a password
jkey pm add my-site

# List all stored passwords
jkey pm ls

# Encrypt/decrypt any file
jkey pv encrypt secret.pdf
jkey pv decrypt secret.pdf.jkey -o secret.pdf
```

## Project Structure

```
src/
└── jkey/
    ├── __init__.py
    ├── __main__.py              # python -m jkey entry point (calls cli.main(); equivalent to `jkey` CLI)
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
    │   ├── import_csv.py        # Import passwords from browser CSV export
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
.claude/
├── settings.local.json          # Local permission allowlist for dev commands
└── skills/
    └── python-expert/           # Custom skill: senior Python developer expertise for code review & best practices
```

## Architecture

### Layered Design

```
CLI (cli.py) → Domain modules (2fa/ pm/ rc/) → Vault core (pv/core.py) → Crypto (aes.py)
```

- **`aes.py`** — Pure-Python AES-256-CBC + HMAC-SHA256. Has zero external dependencies. Exposes only `encrypt(dict, password) → dict` and `decrypt(dict, password) → dict | None`, plus lower-level `aes_cbc_encrypt`, `aes_cbc_decrypt`, and `derive_key` for binary file encryption/decryption. Uses a precomputed 256×256 GF(2^8) multiplication table for performance. PBKDF2-HMAC-SHA256 with 600,000 iterations. AES-256 with 14 rounds and 8-word key expansion.
- **`pv/core.py`** — Vault session manager and the sole data-access layer. Module-level globals (`_session_password`, `_totp_cache`, `_passwords_cache`, `_recovery_cache`) track unlocked state. All domain modules read/write through its `load_*`/`save_*` functions. Also manages QR image storage. Uses `portalocker` for cross-platform file locking (shared locks for reads, exclusive for writes) — replaces the old POSIX-only `fcntl.flock`.
- **Domain modules** (`2fa/`, `pm/`, `rc/`) — Each implements CLI command handlers. They import from `pv.core` or their own `core.py` for data access; never touch `aes.py` directly. `pm/core.py` is a thin re-export layer: it re-exports `load_passwords` and `save_passwords` from `pv.core` so that `pm/` modules can import from their sibling `core.py` instead of reaching across to `pv.core` directly. `pm/import_csv.py` handles browser CSV password imports with encoding auto-detection (utf-8-sig, utf-8, utf-16, latin-1), flexible column-alias matching (20+ recognized header names across name/url/username/password), and three duplicate-resolution modes (skip/overwrite/rename). Name extraction uses the `name` column if present, falling back to URL hostname → username → `entry-N`. If a username column exists and differs from the extracted name, the entry is stored as `name (username)`. The `--replace` flag clears **all** existing passwords before importing — a destructive operation that replaces the entire password store with the CSV contents.
- **`cli.py`** — argparse entry point. Uses `importlib.import_module()` for **lazy imports**: each subcommand's module is only imported when that subcommand is invoked, keeping startup fast. The core dispatch helper is `_call(mod_name, func_name, *args)` which does `getattr(importlib.import_module(mod_name), func_name)(*args)`. Because the `2fa` package name starts with a digit, imports use `importlib.import_module("jkey.2fa...")` — normal `from jkey.2fa import ...` is invalid syntax. All three `ls` subcommands (`2fa ls`, `pm ls`, `rc ls`) return structured data from their core functions; `cli.py` handles printing (sorted alphabetically, case-insensitive keyword filtering). Other commands print internally within their domain modules. **Routing note:** `_2fa`, `_rc`, and `_pv` use a route-dict pattern (`{action: (mod, func, (arg_names))}`); `_pm` uses an if/elif chain instead — when adding new subcommands, follow the pattern of the existing handler for that domain.

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
- `JKEY_PASS` env var is checked after session load fails; if set but incorrect, returns error (no fallthrough to interactive prompt). Export commands do fall through to interactive re-prompt when `JKEY_PASS` is wrong.
- Export commands re-verify the master password via `getpass` even when unlocked, as a safety measure. `JKEY_PASS` satisfies this re-verification.

### File I/O (Atomic Writes)

`_write_jkey()` writes to a `.tmp` file with `O_TRUNC` (overwrites any stale tmp from crashed writes), then uses `os.replace()` (atomic on POSIX). Under exclusive `_lock_vault()`, no race condition. Files created with mode 600. QR image filenames sanitized by replacing invalid filesystem characters (`<>:"/\|?*`) with underscores.

**Platform notes:** `os.chmod(0o600)` and `os.makedirs(mode=0o700)` enforce strict permissions on Linux/macOS but have limited effect on Windows (only the read-only flag is honored). File locking via `portalocker` works on all three platforms (uses `fcntl.flock` on Linux, `fcntl.lockf` on macOS, `msvcrt.locking` on Windows). Config directory is `~/.config/jkey/` on Linux/macOS and `%APPDATA%/jkey/` on Windows.

### Password Generation

`pm/get.py` uses Python's `secrets` module (CSPRNG) with `SystemRandom().shuffle()` for final character ordering. Character sets: lowercase, uppercase, digits, and `!@#$%^&*()_+-=[]{}|;:,.<>?/` (no spaces). At least one character set must be enabled; length must be ≥ the number of enabled sets (one guaranteed char per set). Raises `ValueError` on invalid config.

### Vault Initialization

`pv/init.py` checks password strength via `_check_password_strength()`: minimum 8 characters, recommends 12+ with 3 of 4 character classes (upper, lower, digit, special).

### TOTP Algorithm

`2fa/core.py` implements RFC 4226 (HOTP) and RFC 6238 (TOTP). `totp()` is fixed at 6 digits with a 30-second interval — not configurable. `_b32_decode()` handles base32 with automatic padding and whitespace stripping. `_validate_b32_secret()` is used by `2fa/add.py` to validate secrets extracted from QR codes.

### Key Conventions

- **Vault-first data access:** domain modules never read/write encrypted files or touch `aes.py` directly. All data access goes through `pv.core` load/save APIs (`load_totp`, `save_totp`, `load_passwords`, `save_passwords`, `load_recovery`, `save_recovery`).
- **Interactive prompts guard against EOF/Ctrl-C:** all `input()` and `getpass.getpass()` calls are wrapped in `try/except (EOFError, KeyboardInterrupt)` to gracefully handle pipe termination and user cancellation — print a newline, then return `None` or exit cleanly.
- **`_write_secure_text()` / `_write_secure_bytes()`:** `pv.core` provides helpers for writing non-encrypted files (exports, session) with mode 600 permissions. Both support `atomic=True` (`.tmp` + `os.replace()`) for crash-safe writes.
- **CLI handlers print-and-return:** operational failures are surfaced as user-facing messages and early returns, not raised exceptions. Domain modules should follow the same pattern.
- **Cross-feature account removal:** removing a 2FA account (`2fa rm`) also prompts to delete matching recovery codes. Keep this coupling in mind when modifying either domain.
- **Dynamic imports for `2fa`:** because `2fa` starts with a digit, `from jkey.2fa import ...` is invalid Python syntax. Always use `importlib.import_module("jkey.2fa...")` — the CLI already does this, and tests follow the same pattern.
- **List commands share an output pattern:** sort keys alphabetically and apply case-insensitive keyword filtering. `cli.py` handles printing for all three `ls` subcommands.
- **Export builder pattern:** `pv/export.py` separates `_build_*_content()` (pure data → string) from `_export_*()` (content + file I/O). This lets tests verify output correctness without touching the filesystem. Output formats: TOTP → JSON, passwords → CSV (`name,password`), recovery → plain text (`Account: <name>` blocks), QR → `.jpg` files. New export formats should follow this split. Export re-verification: if `JKEY_PASS` matches the session password, the confirmation prompt is skipped; if `JKEY_PASS` is set but wrong, falls through to interactive `getpass`; if `JKEY_PASS` is unset, always prompts.
- **Backup and migration:** back up `~/.config/jkey/` (excluding `.session`) to migrate to another machine.
- **`__init__.py` is intentionally empty:** the package exposes no public library API — it is purely a CLI tool. All functionality is accessed through `jkey` subcommands.
- **Test isolation via monkeypatching:** use `conftest.py` fixtures (`vault_dir`, `vault`) rather than touching real `~/.config/jkey`. Tests that need to bypass password prompts set `JKEY_PASS` in the environment.

## Testing

### Fixtures (conftest.py)

- **`vault_dir`** — Creates a temp directory and monkeypatches all `pv.core` path constants (`CONFIG_DIR`, `TOTP_FILE`, etc.) to point there. Cleans up module-level cache globals after each test.
- **`vault`** — Returns an initialized-and-unlocked `pv.core` module scoped to the temp directory. Use for tests that need a ready vault.
- **`mock_getpass`** — Factory fixture that monkeypatches `getpass.getpass` to return a fixed password. Call as `mock_getpass(pw="custom-pw")` to set the password.

### Test patterns
- Tests access private functions via `importlib.import_module("jkey.2fa.core")._hotp` — the same lazy-import pattern used by the CLI.
- `test_aes.py::TestV2Compat` manually constructs v2-format ciphertexts to verify backward compatibility.
- TOTP tests include RFC 4226 test vectors (counter 0–9) against known HOTP values.
- Tests that call export functions create fake `args` objects via `type("Args", (), {"type": "totp", "output": None})()` rather than going through argparse.
- `test_list_and_export_paths.py` mocks opencv with `_FakeImage`, `_FakeDetector`, `_FakeEncoded` classes; opencv-dependent tests use `@pytest.mark.skipif` guarding `importlib.import_module("jkey.2fa.add").cv2`.
- Coverage configured in `pyproject.toml` (`[tool.coverage.run]` / `[tool.coverage.report]`).

## Data files

```
~/.config/jkey/
├── .session           # Session cache — plain JSON, mode 600 (5 min activity-based timeout)
├── .lock              # portalocker cross-platform lock file
├── totp.jkey          # Encrypted TOTP secrets: {name: base32_secret}
├── passwords.jkey     # Encrypted passwords: {name: password}
├── recovery.jkey      # Encrypted recovery codes: {account: [code, ...]}
└── qr/
    └── <name>.jkey    # Encrypted QR images (JPEG bytes base64-encoded)
```

On Windows, `CONFIG_DIR` falls back to `%APPDATA%/jkey` instead of `~/.config/jkey`.

`.gitignore` excludes `.venv`, `.python-version`, `__pycache__`, `*.pyc`, `*.tmp`, `.ruff_cache/`, `*.egg-info/`, `dist/`.

<!-- code-review-graph MCP tools -->
## MCP Tools: code-review-graph

**IMPORTANT: This project has a knowledge graph. ALWAYS use the
code-review-graph MCP tools BEFORE using Grep/Glob/Read to explore
the codebase.** The graph is faster, cheaper (fewer tokens), and gives
you structural context (callers, dependents, test coverage) that file
scanning cannot.

### When to use graph tools FIRST

- **Exploring code**: `semantic_search_nodes_tool` or `query_graph_tool` instead of Grep
- **Understanding impact**: `get_impact_radius_tool` instead of manually tracing imports
- **Code review**: `detect_changes_tool` + `get_review_context_tool` instead of reading entire files
- **Finding relationships**: `query_graph_tool` with callers_of/callees_of/imports_of/tests_for
- **Architecture questions**: `get_architecture_overview_tool` + `list_communities_tool`

Fall back to Grep/Glob/Read **only** when the graph doesn't cover what you need.

### Key Tools

| Tool | Use when |
| ------ | ---------- |
| `detect_changes_tool` | Reviewing code changes — gives risk-scored analysis |
| `get_review_context_tool` | Need source snippets for review — token-efficient |
| `get_impact_radius_tool` | Understanding blast radius of a change |
| `get_affected_flows_tool` | Finding which execution paths are impacted |
| `query_graph_tool` | Tracing callers, callees, imports, tests, dependencies |
| `semantic_search_nodes_tool` | Finding functions/classes by name or keyword |
| `get_architecture_overview_tool` | Understanding high-level codebase structure |
| `refactor_tool` | Planning renames, finding dead code |

### Workflow

1. The graph auto-updates on file changes (via hooks).
2. Use `detect_changes_tool` for code review.
3. Use `get_affected_flows_tool` to understand impact.
4. Use `query_graph_tool` pattern="tests_for" to check coverage.
