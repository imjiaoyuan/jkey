# Copilot instructions for `jkey`

## Build, test, and lint

Use `uv` for all local development commands.

```bash
# Install dev dependencies
uv sync --group dev

# Lint (matches CI)
uv run ruff check src/ tests/

# Run all tests (matches CI)
uv run pytest tests/

# Run a single test
uv run pytest tests/test_generator.py::TestGeneratePassword::test_default_length

# Build package
uv build
```

CI runs lint on Python 3.13 and tests on 3.10-3.14 (`.github/workflows/ci.yml`).

## High-level architecture

- `jkey.cli:main` is the CLI entrypoint (`jkey` console script). It parses subcommands and dispatches to `2fa`, `rc`, `pm`, and `pv` handlers.
- `jkey.pv.core` is the vault/data backbone used by all command groups:
  - stores encrypted files in `~/.config/jkey/` (`totp.jkey`, `passwords.jkey`, `recovery.jkey`, and `qr/*.jkey`)
  - manages unlock state, in-memory caches, and a cross-process session file (`.session`, 5-minute timeout)
  - exposes shared load/save functions (`load_totp`, `save_totp`, `load_passwords`, `save_passwords`, etc.)
- `jkey.aes` implements the cryptography used everywhere: AES-256-CBC + HMAC-SHA256 with PBKDF2-HMAC-SHA256 key derivation (versioned format; current writes are version 3, tests cover v2 compatibility).
- Feature modules are thin command handlers around `pv.core`:
  - `2fa`: QR decode with OpenCV, TOTP secret storage/list/remove
  - `rc`: recovery code import/list/remove
  - `pm`: password generation/store/list/remove
  - `pv`: lifecycle (init/unlock/lock/set-pw), file encrypt/decrypt, exports (with password re-verification)

## Key conventions in this codebase

- **Vault-first data access:** command modules do not read/write encrypted files directly; they call `pv.core` load/save APIs.
- **CLI behavior is print-and-return:** operational failures are surfaced as user-facing messages and early returns, not raised exceptions.
- **`2fa` module imports are dynamic:** because the package name starts with a digit, imports use `importlib.import_module("jkey.2fa...")` patterns instead of normal `from jkey.2fa import ...`.
- **Account removal is cross-feature:** removing a 2FA account also removes same-name recovery codes (`src/jkey/2fa/rm.py`), so keep TOTP/recovery behavior aligned.
- **List commands follow one output pattern:** sort keys before printing and apply case-insensitive keyword filtering (`2fa ls`, `rc ls`, `pm ls`).
- **Tests isolate vault paths via monkeypatching:** use `tests/conftest.py` fixtures (`vault_dir`, `vault`) rather than touching real `~/.config/jkey`.
- **Non-interactive flows rely on `JKEY_PASS`:** command and test paths use this env var to bypass prompts where needed.
