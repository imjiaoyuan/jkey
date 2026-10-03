# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**jkey** — Python CLI tool and library for password management and TOTP verification. Manages TOTP secrets, website passwords, recovery codes; generates random passwords; and exports plaintext data. All data is encrypted with AES-256-CBC + HMAC-SHA256 and stored in `~/.config/jkey/`, each type in its own file. Pure Python — no OpenSSL or libsodium needed. Cross-platform: Linux, macOS, and Windows. File locking via `portalocker`.

**Dependencies:** `portalocker` (required), `opencv-python-headless` (optional, only needed for `jkey 2fa add` QR scanning). Install with `pip install jkey[qr]` to include QR support. Build backend: `setuptools`.

## Commands

### Development

The project uses a plain venv + pip workflow (no uv). Create and activate once:

```bash
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
```

- `pip install -e ".[dev]"` — Install the package plus dev tools (`pytest>=8`, `pytest-cov>=6`, `ruff>=0.11`)
- `pytest tests/` — Run all tests (coverage auto-configured via pyproject.toml)
- `pytest tests/ -k "test_name"` — Run a single test by name pattern
- `pytest tests/test_generator.py::TestGeneratePassword::test_default_length` — Run a specific test by path
- `ruff check src/ tests/` — Lint (ruff config: `line-length=120`, `target-version=py310`, select `E,F,W,I`)
- `ruff format src/ tests/` — Format
- `python -m build` — Build distribution packages (requires `pip install build`)

Without activating, call the venv tools directly: `.venv/bin/pytest`, `.venv/bin/ruff`, etc.

CI (`.github/workflows/ci.yml`) uses `actions/setup-python`: lint on Python 3.13 (ubuntu only), tests on 3.10–3.14 across **ubuntu-latest, windows-latest, and macos-latest** (`pip install -e ".[dev]"` + `pytest`), and `python -m build` on every matrix OS. PyPI publishing (`.github/workflows/publish.yml`) triggers on `v*` tags and manual dispatch via trusted publishing (`id-token: write`).

### 2FA
- `jkey 2fa ls [keyword]` — List accounts and current TOTP codes (case-insensitive filter)
- `jkey 2fa add <image_path>` — Import account from QR code image (auto-saves image encrypted)
- `jkey 2fa rm <account>` — Remove an account (also prompts to delete matching recovery codes)

### Recovery Codes
- `jkey rc add <file>` — Import recovery codes from file (filename as account name)
- `jkey rc ls [keyword]` — List recovery codes
- `jkey rc rm <account>` — Remove recovery codes

### Password Management
- `jkey pm ls [keyword]` — List/filter stored passwords
- `jkey pm get [-L N] [--no-upper] [--no-lower] [--no-digits] [--no-symbols]` — Generate random password
- `jkey pm add <name>` — Store a password (interactive input)
- `jkey pm edit <name>` — Update an existing password (interactive input)
- `jkey pm rm <name>` — Delete a password
- `jkey pm import <file.csv> [-n] [-v] [--replace] [-d skip|overwrite|rename]` — Import passwords from browser CSV export

### Vault
- `jkey pv init` — Initialize vault (set master password)
- `jkey pv unlock` — Unlock vault
- `jkey pv lock` — Lock vault
- `jkey pv status` — Show vault status (config directory, initialized/unlocked state)
- `jkey pv set-pw` — Change master password
- `jkey pv encrypt <file> [-o output.jkey]` — Encrypt a file
- `jkey pv decrypt <file.jkey> [-o output]` — Decrypt a .jkey file
- `jkey pv export totp [-o file.json]` — Export TOTP secrets (JSON, re-verifies master password)
- `jkey pv export passwords [-o file.csv]` — Export passwords (CSV)
- `jkey pv export recovery [-o file.txt]` — Export recovery codes (TXT)
- `jkey pv export qr -o <dir>` — Export QR code images
- `jkey pv export all -o <dir>` — Export everything
- `jkey backup add <name> <url> [--endpoint URL] [--region R] [--access-key K] [--secret-key S] [-k N] [--no-test] [-f]` — Configure a backup remote (`s3://bucket/prefix` or local path); runs a connectivity probe unless `--no-test`
- `jkey backup ls` — List remotes (credentials masked)
- `jkey backup rm <name> [-y]` — Remove a remote config
- `jkey backup cred <name> [--clear]` — Set/clear inline S3 credentials
- `jkey backup test <name>` — PUT→GET→DELETE connectivity probe
- `jkey backup run [name] [-k N]` — Back up now (omit name = all remotes)
- `jkey backup snaps <name>` — List snapshots on a remote
- `jkey backup restore <name> [-d STAMP] [-o DIR] [--into-vault]` — Restore (safe mode by default; `--into-vault` transactionally overwrites the live vault after confirmation)
- `jkey backup verify <name> [-d STAMP]` — sha256-check remote snapshots

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
    ├── errors.py                # JkeyError — operational failures raised by domain modules
    ├── aes.py                   # AES-256-CBC + HMAC pure Python implementation
    ├── 2fa/
    │   ├── core.py              # TOTP algorithm (RFC 6238)
    │   ├── add.py               # QR code scanning (opencv) and import
    │   ├── ls.py                # List accounts and TOTP codes
    │   └── rm.py                # Remove account
    ├── rc/
    │   ├── add.py               # Import recovery codes
    │   ├── ls.py                # List recovery codes
    │   └── rm.py                # Remove recovery codes (exposes remove_recovery() service used by 2fa rm)
    ├── pm/
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
    └── backup/
        ├── core.py              # Backup orchestration: remotes.json, run/snaps/restore/verify, cmd_backup dispatch
        └── remotes/
            ├── __init__.py      # open_remote(): scheme → backend dispatch
            ├── base.py          # Remote ABC + key whitelist (snapshots/manifests/LATEST only)
            ├── local.py         # Local path / NAS backend (zero deps)
            └── s3.py            # S3 backend (boto3 lazy import, error→JkeyError mapping)
tests/
├── conftest.py                  # Shared fixtures: vault_dir, vault, mock_getpass
├── test_aes.py                  # Encrypt/decrypt roundtrip, v2 compat, tamper resistance
├── test_backup.py               # Backup: config, parsers, local/S3 backends (fake client), lifecycle roundtrip
├── test_cli.py                  # CLI argument parsing and subcommand dispatch
├── test_generator.py            # Password generation: charset, length, uniqueness
├── test_list_and_export_paths.py # List/export function return value paths
├── test_operations.py           # CRUD operations: add, edit, remove across domains
├── test_totp.py                 # RFC 4226 test vectors, base32, TOTP generation
├── test_vault.py                # Vault core: session, lock, set-pw, init, encrypt/decrypt
└── test_vault_commands.py       # Vault CLI commands: init, unlock, lock, status, set-pw
.github/
└── workflows/
    ├── ci.yml                   # CI: ruff lint, pytest (py3.10–3.14), python -m build
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

- **`aes.py`** — Pure-Python AES-256-CBC + HMAC-SHA256. Has zero external dependencies. Exposes only `encrypt(dict, password) → dict` and `decrypt(dict, password) → dict | None`, plus lower-level `aes_cbc_encrypt`, `aes_cbc_decrypt`, and `derive_key` for binary file encryption/decryption. The 256×256 GF(2⁸) multiplication table is built lazily on first use via `_gf_mul_table()` (exp/log tables with generator 3), so importing `aes` on session-cached read paths costs nothing. PBKDF2-HMAC-SHA256 with 600,000 iterations. AES-256 with 14 rounds and 8-word key expansion. `decrypt()` never prints — any failure (wrong password, tampered MAC, malformed data) silently returns `None`.
- **`errors.py`** — defines `JkeyError`. Domain modules raise it on operational failure; `cli.main()` catches it, prints `Error: <msg>` to stderr, and exits 1.
- **`pv/core.py`** — Vault session manager and the sole data-access layer. Module-level globals (`_session_password`, `_totp_cache`, `_passwords_cache`, `_recovery_cache`) track unlocked state. All domain modules read/write through its `load_*`/`save_*` functions; locked-state access raises `JkeyError` and `load_*` returns a **copy** so callers cannot mutate the cache before saving. Also manages QR image storage. Uses `portalocker` for cross-platform file locking (shared locks for reads, exclusive for writes); `portalocker` and `aes` are imported **lazily** (`_lock_vault()`, `_aes()`) so commands that hit the session cache pay neither import. Key public helpers: `ensure_unlocked()` (raises on failure), `unlock_all()`/`verify_password()` (both backed by `_decrypt_all()`), `set_unlocked()` (populate the session right after init without re-deriving keys), `has_session()` (check for a live session file on disk without loading it), `filter_keys()` (shared keyword filter for the three `ls` commands), `prompt_password_confirmed()`/`confirm_weak_password()` (shared interactive prompts), `read_jkey`/`write_jkey`/`write_secure_text`/`write_secure_bytes`. All atomic writes go through `_stage_write()`/`_atomic_write()` (tmp + `os.replace`); `change_master_password()` is transactional — it stages all three re-encrypted files under one lock before committing, and rolls back staged tmp files on failure.
- **Domain modules** (`2fa/`, `pm/`, `rc/`) — Each implements CLI command handlers. They import from `pv.core` for data access; never touch `aes.py` directly. `2fa/add.py` validates the base32 secret (`validate_b32_secret`) before storing and prompts before overwriting an existing account. `pm/import_csv.py` handles browser CSV password imports with encoding auto-detection (utf-8-sig, utf-8, utf-16, latin-1), flexible column-alias matching (20+ recognized header names across name/url/username/password), and three duplicate-resolution modes (skip/overwrite/rename). Name extraction uses the `name` column if present, falling back to URL hostname → username → `entry-N`. If a username column exists and differs from the extracted name, the entry is stored as `name (username)`. The `--replace` flag clears **all** existing passwords before importing — a destructive operation that replaces the entire password store with the CSV contents (dry-run previews correctly simulate the replace). When `--replace` is used but every row is skipped, the now-empty store is still persisted.
- **`cli.py`** — argparse entry point. Uses `importlib.import_module()` for **lazy imports**: each subcommand's module is only imported when that subcommand is invoked, keeping startup fast. `importlib.metadata` is imported only inside `_VersionAction` so `-v/--version` does not slow every other invocation. The core dispatch helper is `_call(mod_name, func_name, *args)` which does `getattr(importlib.import_module(mod_name), func_name)(*args)`. Because the `2fa` package name starts with a digit, imports use `importlib.import_module("jkey.2fa...")` — normal `from jkey.2fa import ...` is invalid syntax. **All four domain dispatchers use the same route-dict pattern** `{action: (mod, func, extractor)}` where `extractor(args)` returns the positional-arg tuple (`_noargs` for zero-arg commands) — follow it when adding subcommands. All three `ls` subcommands (`2fa ls`, `pm ls`, `rc ls`) return structured data from their core functions; `cli.py` handles printing (sorted alphabetically, case-insensitive keyword filtering via the shared `_no_match()` helper). Other commands print internally within their domain modules. `pm get`'s `ValueError` from the generator is converted to `JkeyError` at the dispatch site. **Exit codes:** 0 = operation completed (including `ls` with no matches); 1 = failure/cancellation (`JkeyError` caught in `main()`); 130 = Ctrl-C.

### Encryption Format

Data files (`.jkey`) are JSON objects with base64-encoded fields. Version history:

| Version | PBKDF2 Output | Enc Key | MAC Key |
|---------|--------------|---------|---------|
| 1–2 | 32 bytes | bytes 0–32 | same as enc key |
| 3 (current) | 64 bytes | bytes 0–32 | bytes 32–64 |

`aes.decrypt()` handles all versions transparently. `aes.encrypt()` always produces v3. The `mac` covers `iv + ciphertext` (encrypt-then-MAC). Tampered ciphertext or MAC returns `None`.

### Session Management

- On unlock, the master password and decrypted vault data are cached in memory (`_session_password`, `_totp_cache`, etc.) and persisted as a per-terminal ticket under `~/.config/jkey/sessions/` (mode 600) with a 5-minute activity-based TTL (configurable via `JKEY_SESSION_TIMEOUT` env var). Like `sudo`'s `tty_tickets`: each terminal window authenticates separately — unlocking in window A never leaves a usable ticket for window B. Processes without a controlling TTY (pipes, cron, CI) share one `"none"` slot; on Windows (no `os.ttyname`) everything shares that slot.
- Session format `sv=3`: plain JSON with `password`, `totp`, `passwords`, `recovery`, `expires`, `vault_fp` fields. `vault_fp` is a hash of the on-disk vault files; if any other process replaced/rewrote them since the ticket was saved (write from another terminal, `pv set-pw`, backup restore), `_load_session()` rejects the stale ticket. Older `sv=2`/`sv=1` formats are rejected — user re-enters password once after upgrade. The legacy `~/.config/jkey/.session` file is deleted on first write.
- On next CLI invocation in the same terminal, `_load_session()` reads that terminal's ticket without requiring the master password. Every successful load rewrites the ticket to reset `expires` (activity-based sliding timeout).
- If the ticket is missing, expired, malformed, fingerprint-mismatched, or `sv` older than 3: `_load_session()` clears the stale ticket and returns `False`, then `ensure_unlocked()` falls back to `unlock_all()` which re-decrypts vault files and saves a new sv=3 ticket. `_load_session()` never raises on bad session data.
- `has_session(this_terminal_only=False)` reports whether a live ticket exists **without** loading it or touching in-memory state. Default is the global view (any terminal — used by `pv status`/`pv lock`); `pv unlock` passes `this_terminal_only=True` so it reports only the calling terminal's own ticket.
- `lock()` drops the in-memory cache and deletes **every** terminal's ticket (`_clear_all_sessions()`); operations that replace vault files on disk (backup restore `--into-vault`) must call `core.lock()` afterwards so no stale cache can be written back over the new files.
- Failed password attempts use exponential backoff (2^attempt seconds, capped at 8), max 3 attempts, then `ensure_unlocked()` raises `JkeyError("Failed to unlock vault.")`.
- `JKEY_PASS` env var is checked after session load fails; if set but incorrect, `JkeyError` is raised immediately (no fallthrough to interactive prompt). Export commands do fall through to interactive re-prompt when `JKEY_PASS` is wrong.
- Export commands re-verify the master password via `getpass` even when unlocked, as a safety measure. `JKEY_PASS` satisfies this re-verification.

### File I/O (Atomic Writes)

`write_jkey()` writes to a `.tmp` file with `O_TRUNC` (overwrites any stale tmp from crashed writes), then uses `os.replace()` (atomic on POSIX). Under exclusive `_lock_vault()`, no race condition. Files created with mode 600. `write_secure_text()`'s non-atomic branch opens the target with `os.open(..., 0o600)` (not plain `open()`) to avoid a brief umask-dependent permission window. QR image filenames sanitized by replacing invalid filesystem characters (`<>:"/\|?*`) with underscores. `change_master_password()` stages all three re-encrypted files as tmps under one lock, then commits them with `os.replace`; any failure unlinks the staged tmps and raises `JkeyError`, leaving the old files intact.

**Platform notes:** `os.chmod(0o600)` and `os.makedirs(mode=0o700)` enforce strict permissions on Linux/macOS but have limited effect on Windows (only the read-only flag is honored). File locking via `portalocker` works on all three platforms (uses `fcntl.flock` on Linux, `fcntl.lockf` on macOS, `msvcrt.locking` on Windows). Config directory is `~/.config/jkey/` on Linux/macOS and `%APPDATA%/jkey/` on Windows.

### Password Generation

`pm/get.py` uses Python's `secrets` module (CSPRNG) with `SystemRandom().shuffle()` for final character ordering. Character sets: lowercase, uppercase, digits, and `!@#$%^&*()_+-=[]{}|;:,.<>?/` (no spaces). At least one character set must be enabled; length must be ≥ the number of enabled sets (one guaranteed char per set). Raises `ValueError` on invalid config.

### Vault Initialization

`pv/init.py` checks password strength via `check_password_strength()` (defined in `pv/core.py`): minimum 8 characters, recommends 12+ with 3 of 4 character classes (upper, lower, digit, special). The shared `confirm_weak_password()` helper prints the warning and asks "Continue anyway? (y/N)". The strength check, confirm-prompt, and password confirmation only run for interactive entry; a password supplied via `JKEY_PASS` is accepted as-is.

### TOTP Algorithm

`2fa/core.py` implements RFC 4226 (HOTP) and RFC 6238 (TOTP). `totp()` is fixed at 6 digits with a 30-second interval — not configurable. `_b32_decode()` handles base32 with automatic padding and whitespace stripping. `validate_b32_secret()` is used by `2fa/add.py` to reject invalid secrets extracted from QR codes before they enter the vault.

### Key Conventions

- **Vault-first data access:** domain modules never read/write encrypted files or touch `aes.py` directly. All data access goes through `pv.core` load/save APIs (`load_totp`, `save_totp`, `load_passwords`, `save_passwords`, `load_recovery`, `save_recovery`). Accessing these while locked raises `JkeyError`. The `load_*` functions return a shallow copy of the cached dict — mutate it and pass it to `save_*`, never assume mutations hit the cache automatically.
- **Error handling via `JkeyError`:** domain modules **raise `jkey.errors.JkeyError`** when the requested operation does not complete (failure, user cancellation, password mismatch, unlock failure); they never print error messages themselves. `cli.main()` catches it, prints `Error: <msg>` to stderr, and exits 1. Success and informational messages (e.g. "Recovery codes kept.", ls no-match notices) print to stdout with exit 0.
- **Interactive prompts guard against EOF/Ctrl-C:** all `input()` and `getpass.getpass()` calls are wrapped in `try/except (EOFError, KeyboardInterrupt)` — print a newline, then raise `JkeyError` (cancelled). Shared helpers: `prompt_password()` (single), `prompt_password_confirmed()` (double + match check), `confirm_weak_password()` (warning + y/N).
- **`write_secure_text()` / `write_secure_bytes()`:** `pv.core` provides helpers for writing non-encrypted files (exports, session) with mode 600 permissions. Both support `atomic=True` (`.tmp` + `os.replace()`) for crash-safe writes.
- **Cross-feature account removal:** `rc/rm.py` exposes `remove_recovery(account) -> bool` as a service; `2fa rm` prompts the user, then calls it. Keep this coupling in mind when modifying either domain.
- **Dynamic imports for `2fa`:** because `2fa` starts with a digit, `from jkey.2fa import ...` is invalid Python syntax. Always use `importlib.import_module("jkey.2fa...")` — the CLI already does this, and tests follow the same pattern.
- **Never bind `pv.core` path constants at import time:** tests monkeypatch `core.CONFIG_DIR`/`TOTP_FILE`/etc. as module attributes *after* import. Modules needing these paths must access them through the module object (`from jkey.pv import core` → `core.TOTP_FILE`), not via `from jkey.pv.core import TOTP_FILE` at module top level — that freezes the pre-patch value. (Functions from `pv.core` are safe to import directly.)
- **List commands share an output pattern:** the three `ls` core functions use `filter_keys(data, keyword)` (sorted keys, case-insensitive substring filter); `cli.py` handles printing via `_no_match()`.
- **Export builder pattern:** `pv/export.py` separates `_build_*_content()` (pure data → string) from `_export_*()` (content + file I/O). This lets tests verify output correctness without touching the filesystem. Output formats: TOTP → JSON, passwords → CSV (`name,password`), recovery → plain text (`Account: <name>` blocks), QR → `.jpg` files. New export formats should follow this split. Export re-verification: if `JKEY_PASS` matches the session password, the confirmation prompt is skipped; otherwise a `getpass` prompt is required and a mismatch raises `JkeyError`.
- **Backup and migration:** `jkey backup` pushes the encrypted `.jkey` files as timestamped tar.gz snapshots (plus a `.sha256` manifest and a `LATEST` pointer per remote). No master password involved — ciphertext in, ciphertext out; `sessions/` tickets are never included. See **Backup feature** below.
- **Backup feature (`pv/backup/`):**
  - **Ciphertext-only backups:** snapshots are tar.gz archives of the already-encrypted vault files (`totp.jkey`, `passwords.jkey`, `recovery.jkey`, `qr/*.jkey`) — backup/restore never needs the master password and never touches plaintext. `sessions/` and `.lock` are structurally excluded (not in `_VAULT_FILES`).
  - **Remote layout:** `<YYYYMMDD-HHMMSS>.tar.gz` snapshot + `<stamp>.sha256` sha256 manifest + `LATEST` pointer, all under an optional prefix. Retention: `-k/--keep` override, else the remote's configured `keep`, else default 5; pruning deletes oldest snapshot+manifest pairs beyond the limit.
  - **Remotes config:** `remotes.json` in `CONFIG_DIR` (mode 600, via `core.write_secure_text`), computed through `_remotes_file()` — never bind the path at import time (same monkeypatch rule as `pv.core`). Inline `access_key`/`secret_key` for S3 remotes; absent → boto3 default chain. `ls` output always masks both (`_redacted()`), errors mask AKID-shaped tokens (`s3._wrap_s3_error`).
  - **Backends:** `Remote` ABC (`put/get/list_keys/delete/probe`). `LocalRemote` (`file://` or bare path, zero deps); `S3Remote` (boto3 lazy-imported — missing boto3 raises `JkeyError("... pip install jkey[s3]")`). Scheme dispatch via `remotes.open_remote(cfg)`. `probe()` is a full PUT→GET(read-back)→DELETE roundtrip with a manifest-style key, so read-only IAM policies fail loudly.
  - **Safety rails:** `restore` without `--into-vault` only unpacks to `-o DIR` (default `./jkey-restore-<stamp>`); `--into-vault` confirms (`input()`), stages via `core.write_jkey`, and is transactional. Archive members are validated against the restore dir (`escapes restore dir` rejection); `-d` stamps must pass `valid_snapshot()` (no path traversal). `verify` checks remote bytes against the `.sha256` manifest.
  - **Tests:** S3 backend tested with an in-memory `FakeS3Client` injected as `r._client`; `_stamp()` monkeypatched for deterministic snapshot names.
- **`__init__.py` is intentionally empty:** the package exposes no public library API — it is purely a CLI tool. All functionality is accessed through `jkey` subcommands.
- **Test isolation via monkeypatching:** use `conftest.py` fixtures (`vault_dir`, `vault`) rather than touching real `~/.config/jkey`. Tests that need to bypass password prompts set `JKEY_PASS` in the environment.

## Testing

### Fixtures (conftest.py)

- **`vault_dir`** — Creates a temp directory and monkeypatches all `pv.core` path constants (`CONFIG_DIR`, `TOTP_FILE`, etc.) to point there. Cleans up module-level cache globals after each test.
- **`vault`** — Returns an initialized-and-unlocked `pv.core` module scoped to the temp directory. Use for tests that need a ready vault.

### Test patterns
- Error paths are asserted with `pytest.raises(JkeyError, match="...")` — error messages double as match patterns; keep them stable when rewording.
- Tests access private functions via `importlib.import_module("jkey.2fa.core")._hotp` — the same lazy-import pattern used by the CLI.
- Tests that patch a helper used by a fixture must use a separate `pytest.MonkeyPatch()` scope — calling `monkeypatch.undo()` inside a test also reverts the `vault_dir` fixture's path patches (fixtures share the test's monkeypatch instance).
- `test_aes.py::TestV2Compat` manually constructs v2-format ciphertexts to verify backward compatibility.
- TOTP tests include RFC 4226 test vectors (counter 0–9) against known HOTP values.
- Tests that call export functions create fake `args` objects via `type("Args", (), {"type": "totp", "output": None})()` rather than going through argparse.
- `test_list_and_export_paths.py` mocks opencv with `_FakeImage`, `_FakeDetector`, `_FakeEncoded` classes; opencv-dependent tests use `@pytest.mark.skipif` guarding `importlib.import_module("jkey.2fa.add").cv2` (cv2 must stay a module-level attribute, evaluated at collection time).
- The unlock-backoff tests patch `time.sleep` (`monkeypatch.setattr("time.sleep", lambda s: None)`) to skip the 2s/4s waits.
- Coverage configured in `pyproject.toml` (`[tool.coverage.run]` / `[tool.coverage.report]`).

## Data files

```
~/.config/jkey/
├── sessions/          # Per-terminal session tickets — plain JSON, mode 600 (5 min activity-based timeout)
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
scanning cannot. The server is configured in `.mcp.json` (launches the
`code-review-graph` executable installed in the project `.venv`); graph
data lives in `.code-review-graph/graph.db`.

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
