# AGENTS.md

Read this before changing anything.

## What this is

**jkey** is a pure-Python, cross-platform (Linux/macOS/Windows) CLI password manager and TOTP verifier. All data is AES-256-CBC + HMAC-SHA256 encrypted in `~/.config/jkey/`, one file per data type; no OpenSSL or libsodium. Package source lives in `src/jkey/` (Python ≥ 3.10), tests in `tests/`. User-facing command reference: [README.md](README.md).

## Commands

Plain venv + pip, no uv. The venv shares system site-packages, so its console scripts are incomplete — invoke dev tools via `python -m`:

```bash
python3 -m venv --system-site-packages .venv   # create once
source .venv/bin/activate                      # Windows: .venv\Scripts\activate
pip install -e ".[dev]"                        # pytest, pytest-cov, ruff

python -m pytest tests/                        # all tests (coverage on by default via pyproject addopts)
python -m pytest tests/ -k "test_name"         # by keyword
python -m pytest tests/test_vault.py::TestSession::test_expire   # single test
python -m ruff check src/ tests/               # lint (line-length 120, py310 target, E/F/W/I)
python -m ruff format src/ tests/              # format
python -m build                                # sdist+wheel (needs: pip install build)
```

Tests must never touch the real `~/.config/jkey` — use the `conftest.py` fixtures; set `JKEY_PASS` to bypass password prompts. CI (`.github/workflows/ci.yml`) runs `ruff check src/ tests/` on Python 3.13 (ubuntu only), then `pip install -e ".[dev]"` + `pytest tests/` + `python -m build` on 3.10–3.14 × ubuntu/windows/macos. Publishing (`.github/workflows/publish.yml`) fires on `v*` tags via trusted publishing; a release is a version bump in `pyproject.toml` + git tag.

## Architecture

Layering: CLI (`cli.py`) → domain modules (`2fa/`, `pm/`, `rc/`) → vault core (`pv/core.py`) → crypto (`aes.py`).

- `cli.py` — argparse entry, lazy `importlib` imports per subcommand; route-dict dispatch `{action: (mod, func, extractor)}` per domain; owns all `ls` printing and exit codes (0 = done incl. no matches, 1 = `JkeyError`, 130 = Ctrl-C).
- `errors.py` — `JkeyError`, the only operational-failure type.
- `aes.py` — pure-Python AES-256-CBC + HMAC-SHA256 (encrypt-then-MAC), PBKDF2-HMAC-SHA256 600k iterations, lazy GF(2⁸) table. Public surface: `encrypt`/`decrypt` (dict-level), `aes_cbc_encrypt`/`aes_cbc_decrypt`/`derive_key` (binary). `decrypt` never prints — any failure returns `None`.
- `2fa/`, `rc/`, `pm/` — one module per CLI action. TOTP (RFC 4226/6238) is fixed at 6 digits / 30 s. `pm/get.py` generates via `secrets`. `pm/import_csv.py` handles browser CSV imports (encoding/column auto-detect, skip/overwrite/rename, destructive `--replace`).
- `pv/core.py` — sole data-access layer and session manager: `load_*`/`save_*` for the three data types, QR storage, portalocker locking (shared read / exclusive write), `filter_keys()` shared by the `ls` commands, shared prompt helpers, atomic writes (unique tmp + fsync + `os.replace`). `load_*` returns a copy; locked access raises `JkeyError`. `portalocker` and `aes` are imported lazily so session-cached paths stay fast.
- `pv/session_store.py` — session passwords live only in native OS credential stores (Secret Service / macOS Keychain / Windows Credential Manager). No file-backed fallback, ever.
- `pv/transaction.py` — recoverable multi-file vault updates (stage → commit → rollback with fsync); call only while holding the vault lock. Used by master-password changes and restore-style flows.
- `pv/export.py` — export commands split into pure `_build_*_content()` and I/O-only `_export_*()`.
- `pv/backup/` — ciphertext-only snapshots: unique tar.gz + `.sha256` manifest + `LATEST` pointer per remote; sessions/ and `.bak` files excluded; uploads verified by read-back before pruning. `config.py` owns remotes.json I/O, `archive.py` builds/verifies/extracts snapshot archives, `core.py` keeps the command handlers and the restore pipeline; `remotes/` holds the backend ABC plus `local.py`, `s3.py` (lazy boto3) and `rclone.py` behind `open_remote()` scheme dispatch. Backend configuration details: [docs/backup.md](docs/backup.md).
- `__init__.py` is intentionally empty — no public library API, CLI only.

## Conventions

- **Vault-first data access:** domain modules never touch encrypted files or `aes.py` directly — only `pv.core` load/save APIs.
- **`JkeyError` contract:** domain modules raise `JkeyError`; they never print error messages. Error strings double as `pytest.raises(match=...)` patterns — keep them stable when rewording.
- **Prompt safety:** every `input()`/`getpass` call guards `EOFError`/`KeyboardInterrupt` (print newline, raise `JkeyError`). Reuse `pv.core` prompt helpers instead of writing new ones.
- **Digit-led package:** `from jkey.2fa import ...` is invalid syntax — always `importlib.import_module("jkey.2fa...")` (CLI and tests already do).
- **No import-time path binding:** never `from jkey.pv.core import TOTP_FILE`; tests monkeypatch these constants as module attributes, so access them through the module object (`core.TOTP_FILE`). Functions may be imported directly.
- **Output split:** `ls` core functions return structured data (CLI prints, sorted, via `filter_keys` + `_no_match`); other commands print internally and return nothing meaningful.
- **Cross-feature coupling:** `rc/rm.py` exposes `remove_recovery()`; `2fa rm` calls it after prompting. Update both sides together.
- **Test patterns:** fixtures `vault_dir` / `vault` from `conftest.py`; patch helpers used by a fixture with a separate `pytest.MonkeyPatch()` instance (fixtures share the test's monkeypatch); patch `time.sleep` in backoff tests; access private functions via `importlib.import_module`.
- **Commits:** conventional style, single line, no body — `type(scope): lowercase imperative subject` (types in use: feat, fix, docs, chore, ci). Version releases are `chore: bump version to X.Y.Z`. Do not `git push` unless asked in the current session.

## Storage / data layout

Runtime layout (`~/.config/jkey/`, `%APPDATA%/jkey` on Windows) with per-file contents: README → "How It Works". Encryption format: `.jkey` files are JSON with base64 fields; v3 (current) uses 64-byte PBKDF2 output split into enc key (0–32) and MAC key (32–64), v1–2 reuse the enc key as MAC key; `aes.decrypt` transparently handles all versions, `encrypt` always writes v3. `sessions/` holds per-terminal tickets (`sv=4`, expiry + vault fingerprint only — no secrets, never backed up).
