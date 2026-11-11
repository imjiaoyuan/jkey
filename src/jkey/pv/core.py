import base64
import contextlib
import hashlib
import json
import os
import platform
import sys
import time

from jkey.errors import JkeyError
from jkey.pv import session_store, transaction


def _aes():
    """Import AES only when encryption or decryption is needed."""
    from jkey import aes

    return aes


if platform.system() == "Windows":
    _config_base = os.environ.get("APPDATA", os.path.expanduser("~"))
    CONFIG_DIR = os.path.join(_config_base, "jkey")
else:
    CONFIG_DIR = os.path.join(os.path.expanduser("~"), ".config", "jkey")
TOTP_FILE = os.path.join(CONFIG_DIR, "totp.jkey")
PASSWORDS_FILE = os.path.join(CONFIG_DIR, "passwords.jkey")
RECOVERY_FILE = os.path.join(CONFIG_DIR, "recovery.jkey")
QR_DIR = os.path.join(CONFIG_DIR, "qr")
SESSION_DIR = os.path.join(CONFIG_DIR, "sessions")
SESSION_TIMEOUT = int(os.environ.get("JKEY_SESSION_TIMEOUT", "300"))
VAULT_LOCK_PATH = os.path.join(CONFIG_DIR, ".lock")
_JKEY_EXT = ".jkey"

_INVALID_FS_CHARS = '<>:"/\\|?*'


def check_password_strength(password: str) -> tuple[bool, str]:
    if len(password) < 8:
        return False, "Password must be at least 8 characters."
    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_special = any(not c.isalnum() for c in password)
    strength_count = sum([has_upper, has_lower, has_digit, has_special])
    if len(password) < 12 and strength_count < 3:
        return False, (
            "Password should be at least 12 characters or include more character types (upper, lower, digits, special)."
        )
    return True, ""


_SANITIZE_TABLE = str.maketrans({ord(ch): ord("_") for ch in _INVALID_FS_CHARS})


def _sanitize_filename(name: str) -> str:
    return name.translate(_SANITIZE_TABLE)


@contextlib.contextmanager
def _lock_vault(shared: bool = False):
    import portalocker

    ensure_dir()
    # Recovery can write; serialize readers too so a crashed transaction is repaired first.
    mode = portalocker.LOCK_EX
    with portalocker.Lock(VAULT_LOCK_PATH, "a+", flags=mode) as _fh:
        transaction.recover(CONFIG_DIR)
        yield


_session_password: str | None = None
_totp_cache: dict | None = None
_passwords_cache: dict | None = None
_recovery_cache: dict | None = None


def ensure_dir():
    os.makedirs(CONFIG_DIR, mode=0o700, exist_ok=True)
    os.makedirs(QR_DIR, mode=0o700, exist_ok=True)
    _remove_legacy_session()
    for path in list(_iter_session_files()):
        _ticket(path)


def password_from_env() -> str | None:
    return os.environ.get("JKEY_PASS")


def prompt_password(prompt: str = "Master password: ") -> str | None:
    import getpass

    try:
        pw = getpass.getpass(prompt)
        return pw if pw else None
    except (EOFError, KeyboardInterrupt):
        print(file=sys.stderr)
        return None


def prompt_password_confirmed(prompt: str, confirm_prompt: str) -> str:
    pw = prompt_password(prompt)
    if not pw:
        raise JkeyError("Password cannot be empty.")
    pw2 = prompt_password(confirm_prompt)
    if pw != pw2:
        raise JkeyError("Passwords do not match.")
    return pw


def confirm_weak_password(password: str) -> bool:
    is_strong, warning = check_password_strength(password)
    if is_strong:
        return True
    print(f"Warning: {warning}")
    try:
        response = input("Continue anyway? (y/N): ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        print()
        return False
    return response == "y"


def filter_keys(data: dict, keyword: str | None) -> list[str]:
    keys = sorted(data.keys())
    if keyword:
        keys = [k for k in keys if keyword.lower() in k.lower()]
    return keys


def _stage_write(path: str, data: bytes) -> str:
    return transaction.stage(path, data)


def _atomic_write(path: str, data: bytes):
    transaction.write(path, data)
    with contextlib.suppress(FileNotFoundError):
        os.unlink(path + ".tmp")


def _terminal_id() -> str:
    """Stable per-terminal id: the controlling TTY, or 'none' when stdin has no TTY.

    sudo-style tty tickets — each terminal window authenticates separately, so unlocking in
    window A never leaves a live ticket for window B. Pipelines/cron (no TTY) share the
    'none' slot, which is the same single-session behavior as before.
    """
    try:
        return os.ttyname(sys.stdin.fileno())
    except (OSError, ValueError, AttributeError):
        return "none"


def _session_file(terminal_id: str | None = None) -> str:
    """Path of one terminal's ticket under SESSION_DIR; tests patch SESSION_DIR."""
    tid = terminal_id if terminal_id is not None else _terminal_id()
    h = hashlib.sha256(tid.encode("utf-8")).hexdigest()[:16]
    return os.path.join(SESSION_DIR, h + ".json")


def _iter_session_files():
    """All ticket files, including expired ones (for lock / status sweeping)."""
    try:
        names = os.listdir(SESSION_DIR)
    except OSError:
        return
    for name in names:
        if name.endswith(".json"):
            yield os.path.join(SESSION_DIR, name)


_LEGACY_SESSION_FILE = os.path.join(CONFIG_DIR, ".session")


def _remove_legacy_session():
    """Remove both legacy plaintext tickets and their interrupted-write leftovers."""
    paths = [_LEGACY_SESSION_FILE, _LEGACY_SESSION_FILE + ".tmp"]
    with contextlib.suppress(OSError):
        paths.extend(os.path.join(SESSION_DIR, name) for name in os.listdir(SESSION_DIR)
                     if name.endswith(".json.tmp"))
    for path in paths:
        with contextlib.suppress(OSError):
            os.unlink(path)


def _vault_fingerprint() -> str:
    """Invalidate cached credentials whenever the encrypted data generation changes."""
    h = hashlib.sha256()
    for path in (TOTP_FILE, PASSWORDS_FILE, RECOVERY_FILE):
        try:
            with open(path, "rb") as f:
                h.update(f.read())
        except OSError:
            pass
    return h.hexdigest()


def _save_session(password, totp, passwords, recovery):
    ensure_dir()
    os.makedirs(SESSION_DIR, mode=0o700, exist_ok=True)
    _remove_legacy_session()
    # Remove obsolete plaintext tickets for every terminal on first use.
    for path in list(_iter_session_files()):
        _ticket(path)
    path = _session_file()
    if not session_store.save(path, password):
        _delete_ticket(path)
        print("Session caching unavailable: no unlocked native OS credential store; "
              "new commands require authentication.", file=sys.stderr)
        return
    payload = {"sv": 4, "expires": time.time() + SESSION_TIMEOUT, "vault_fp": _vault_fingerprint()}
    try:
        _atomic_write(path, json.dumps(payload).encode("utf-8"))
    except OSError as e:
        _delete_ticket(path)
        print(f"Warning: failed to save session cache: {e}", file=sys.stderr)


def _delete_ticket(path):
    session_store.delete(path)
    with contextlib.suppress(FileNotFoundError):
        os.unlink(path)


def _ticket(path):
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        if (not isinstance(data, dict) or data.get("sv") != 4
                or not isinstance(data.get("expires"), (int, float))
                or not time.time() < data["expires"]
                or data.get("vault_fp") != _vault_fingerprint()):
            _delete_ticket(path)
            return None
        return data
    except (OSError, ValueError):
        with contextlib.suppress(OSError):
            _delete_ticket(path)
        return None


def _load_session() -> bool:
    _remove_legacy_session()
    path = _session_file()
    if _ticket(path) is None:
        return False
    password = session_store.load(path)
    if not isinstance(password, str) or not unlock_all(password):
        _delete_ticket(path)
        return False
    return True


def has_session(this_terminal_only: bool = False) -> bool:
    _remove_legacy_session()
    paths = [_session_file()] if this_terminal_only else list(_iter_session_files())
    return any(_ticket(path) is not None and session_store.load(path) is not None for path in paths)


def _clear_session():
    """Remove this terminal's ticket (leave other terminals' tickets alone)."""
    try:
        _delete_ticket(_session_file())
    except FileNotFoundError:
        pass
    except OSError as e:
        print(f"Warning: failed to clear session cache: {e}", file=sys.stderr)


def _clear_all_sessions():
    """Remove every terminal's ticket — used by lock and after vault files are replaced on disk."""
    _remove_legacy_session()
    for path in list(_iter_session_files()):
        try:
            _delete_ticket(path)
        except OSError:
            pass


def read_jkey(path: str) -> dict | None:
    with _lock_vault(shared=True):
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except FileNotFoundError:
            return None
        except (ValueError, OSError) as e:
            raise JkeyError(f"cannot read vault file {path}: {e}") from e


def write_jkey(path: str, encrypted: dict):
    ensure_dir()
    payload = json.dumps(encrypted, indent=4, ensure_ascii=False).encode("utf-8")
    with _lock_vault():
        _atomic_write(path, payload)


def write_secure_text(
    path: str, content: str, encoding: str = "utf-8", newline: str | None = None, atomic: bool = False
):
    if atomic:
        _atomic_write(path, content.encode(encoding))
    else:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding=encoding, newline=newline) as f:
            f.write(content)
        os.chmod(path, 0o600)


def write_secure_bytes(path: str, content: bytes, atomic: bool = False):
    if atomic:
        _atomic_write(path, content)
    else:
        with open(path, "wb") as f:
            f.write(content)
        os.chmod(path, 0o600)


def vault_exists() -> bool:
    if os.path.exists(os.path.join(CONFIG_DIR, ".transaction")):
        with _lock_vault():
            pass
    return any(os.path.exists(p) for p in (TOTP_FILE, PASSWORDS_FILE, RECOVERY_FILE))


def _decrypt_all(password: str) -> dict[str, dict] | None:
    with _lock_vault(shared=True):
        return _decrypt_all_locked(password)


def _decrypt_all_locked(password):
    result = {}
    for path, key in ((TOTP_FILE, "totp"), (PASSWORDS_FILE, "passwords"), (RECOVERY_FILE, "recovery")):
        if not os.path.exists(path):
            continue
        try:
            with open(path, encoding="utf-8") as f:
                encrypted = json.load(f)
        except (OSError, ValueError) as e:
            raise JkeyError(f"cannot read vault file {path}: {e}") from e
        decrypted = _aes().decrypt(encrypted, password)
        if decrypted is None:
            return None
        result[key] = decrypted
    return result or None


def verify_password(password: str) -> bool:
    return _decrypt_all(password) is not None


def unlock_all(password: str) -> bool:
    global _session_password, _totp_cache, _passwords_cache, _recovery_cache
    data = _decrypt_all(password)
    if data is None:
        return False
    _totp_cache = data.get("totp") or {}
    _passwords_cache = data.get("passwords") or {}
    _recovery_cache = data.get("recovery") or {}
    _session_password = password
    _save_session(password, _totp_cache, _passwords_cache, _recovery_cache)
    return True


def ensure_unlocked() -> None:
    if is_unlocked():
        return
    if _load_session():
        return
    if not vault_exists():
        raise JkeyError("Vault not initialized. Run 'jkey pv init' first.")
    pw = password_from_env()
    if pw:
        if unlock_all(pw):
            return
        raise JkeyError("JKEY_PASS environment variable contains incorrect password.")
    for attempt in range(3):
        if attempt > 0:
            time.sleep(min(2**attempt, 8))
        pw = prompt_password()
        if pw is None:
            raise JkeyError("Cancelled.")
        if unlock_all(pw):
            return
        print("Incorrect password. Try again.")
    raise JkeyError("Failed to unlock vault.")


def is_unlocked() -> bool:
    return _session_password is not None


def get_session_password() -> str | None:
    """Return the current session password, or None if vault is locked."""
    return _session_password


def lock():
    global _session_password, _totp_cache, _passwords_cache, _recovery_cache
    _session_password = None
    _totp_cache = None
    _passwords_cache = None
    _recovery_cache = None
    _clear_all_sessions()


def set_unlocked(password: str, totp: dict, passwords: dict, recovery: dict) -> None:
    """Populate the in-memory session without re-deriving keys (used right after init)."""
    global _session_password, _totp_cache, _passwords_cache, _recovery_cache
    _session_password = password
    _totp_cache = totp
    _passwords_cache = passwords
    _recovery_cache = recovery
    _save_session(password, totp, passwords, recovery)


def encrypt_file(path: str, data: dict, password: str):
    write_jkey(path, _aes().encrypt(data, password))


def change_master_password(new_password: str) -> bool:
    global _session_password
    if _session_password is None or _totp_cache is None:
        return False
    with _lock_vault():
        try:
            data = _decrypt_all_locked(_session_password)
            if data is None:
                raise JkeyError("Vault changed; unlock again before changing the password.")
            aes = _aes()
            updates = {}
            for name, key in (("totp.jkey", "totp"), ("passwords.jkey", "passwords"), ("recovery.jkey", "recovery")):
                updates[name] = json.dumps(aes.encrypt(data.get(key, {}), new_password)).encode()
            for name in sorted(os.listdir(QR_DIR)):
                if name.endswith(_JKEY_EXT):
                    path = os.path.join(QR_DIR, name)
                    if os.path.islink(path):
                        raise JkeyError(f"Refusing QR symlink: {name}")
                    with open(path, encoding="utf-8") as f:
                        qr = aes.decrypt(json.load(f), _session_password)
                    if qr is None:
                        raise JkeyError(f"Cannot decrypt QR image {name}; password not changed.")
                    updates[f"qr/{name}"] = json.dumps(aes.encrypt(qr, new_password)).encode()
            transaction.replace(CONFIG_DIR, updates)
        except (OSError, ValueError) as e:
            raise JkeyError(f"failed to re-encrypt vault: {e}") from e
        lock()
        set_unlocked(new_password, data.get("totp", {}), data.get("passwords", {}), data.get("recovery", {}))
    return True


def load_totp() -> dict:
    ensure_unlocked()
    return dict(_totp_cache or {})


def save_totp(data: dict):
    global _totp_cache
    pw = _session_password
    if pw is None:
        raise JkeyError("vault is locked. Changes not saved.")
    encrypt_file(TOTP_FILE, data, pw)
    _totp_cache = data
    _save_session(pw, data, _passwords_cache, _recovery_cache)


def load_passwords() -> dict:
    ensure_unlocked()
    return dict(_passwords_cache or {})


def save_passwords(data: dict):
    global _passwords_cache
    pw = _session_password
    if pw is None:
        raise JkeyError("vault is locked. Changes not saved.")
    encrypt_file(PASSWORDS_FILE, data, pw)
    _passwords_cache = data
    _save_session(pw, _totp_cache, data, _recovery_cache)


def load_recovery() -> dict:
    ensure_unlocked()
    return dict(_recovery_cache or {})


def save_recovery(data: dict):
    global _recovery_cache
    pw = _session_password
    if pw is None:
        raise JkeyError("vault is locked. Changes not saved.")
    encrypt_file(RECOVERY_FILE, data, pw)
    _recovery_cache = data
    _save_session(pw, _totp_cache, _passwords_cache, data)


def _qr_path(name: str) -> str:
    return os.path.join(QR_DIR, f"{_sanitize_filename(name)}{_JKEY_EXT}")


def save_qr_image(name: str, image_data: bytes):
    pw = _session_password
    if pw is None:
        raise JkeyError("vault is locked. Changes not saved.")
    ensure_dir()
    encoded = base64.b64encode(image_data).decode("ascii")
    encrypted = _aes().encrypt({"raw": encoded}, pw)
    write_jkey(_qr_path(name), encrypted)


def delete_qr_image(name: str) -> bool:
    path = _qr_path(name)
    if not os.path.exists(path):
        return False
    try:
        with _lock_vault():
            os.unlink(path)
    except FileNotFoundError:
        return True
    except PermissionError as e:
        print(f"Warning: cannot remove QR backup '{path}': {e}", file=sys.stderr)
        return False
    except OSError as e:
        print(f"Warning: failed to remove QR backup '{path}': {e}", file=sys.stderr)
        return False
    return True


def load_qr_image(name: str) -> bytes | None:
    ensure_unlocked()
    pw = _session_password
    if pw is None:
        return None
    path = _qr_path(name)
    if not os.path.exists(path):
        legacy = os.path.join(QR_DIR, f"{name}{_JKEY_EXT}")
        if not os.path.exists(legacy):
            return None
        path = legacy
    encrypted = read_jkey(path)
    if encrypted is None:
        return None
    data = _aes().decrypt(encrypted, pw)
    if data is None or "raw" not in data:
        return None
    return base64.b64decode(data["raw"])


def list_qr_images() -> list[str]:
    if not os.path.exists(QR_DIR):
        return []
    names = []
    for f in os.listdir(QR_DIR):
        if f.endswith(_JKEY_EXT):
            names.append(f[: -len(_JKEY_EXT)])
    return sorted(names)
