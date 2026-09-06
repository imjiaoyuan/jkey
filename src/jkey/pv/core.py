import base64
import contextlib
import json
import os
import platform
import sys
import time

import portalocker

from jkey import aes
from jkey.errors import JkeyError

if platform.system() == "Windows":
    _config_base = os.environ.get("APPDATA", os.path.expanduser("~"))
    CONFIG_DIR = os.path.join(_config_base, "jkey")
else:
    CONFIG_DIR = os.path.join(os.path.expanduser("~"), ".config", "jkey")
TOTP_FILE = os.path.join(CONFIG_DIR, "totp.jkey")
PASSWORDS_FILE = os.path.join(CONFIG_DIR, "passwords.jkey")
RECOVERY_FILE = os.path.join(CONFIG_DIR, "recovery.jkey")
QR_DIR = os.path.join(CONFIG_DIR, "qr")
SESSION_FILE = os.path.join(CONFIG_DIR, ".session")
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
    ensure_dir()
    mode = portalocker.LOCK_SH if shared else portalocker.LOCK_EX
    with portalocker.Lock(VAULT_LOCK_PATH, "a+", flags=mode) as _fh:
        yield


_session_password: str | None = None
_totp_cache: dict | None = None
_passwords_cache: dict | None = None
_recovery_cache: dict | None = None


def ensure_dir():
    os.makedirs(CONFIG_DIR, mode=0o700, exist_ok=True)
    os.makedirs(QR_DIR, mode=0o700, exist_ok=True)


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
    tmp = path + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(data)
    return tmp


def _atomic_write(path: str, data: bytes):
    os.replace(_stage_write(path, data), path)


def _save_session(password, totp, passwords, recovery):
    ensure_dir()
    payload = {
        "sv": 3,
        "password": password,
        "totp": totp,
        "passwords": passwords,
        "recovery": recovery,
        "expires": time.time() + SESSION_TIMEOUT,
    }
    try:
        _atomic_write(SESSION_FILE, json.dumps(payload).encode("utf-8"))
    except OSError as e:
        print(f"Warning: failed to save session cache: {e}", file=sys.stderr)


def _load_session() -> bool:
    global _session_password, _totp_cache, _passwords_cache, _recovery_cache
    try:
        with open(SESSION_FILE) as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError):
        return False
    if not isinstance(data, dict) or data.get("sv", 1) < 3:
        return False
    if time.time() >= data["expires"]:
        _clear_session()
        return False
    _session_password = data["password"]
    _totp_cache = data["totp"]
    _passwords_cache = data["passwords"]
    _recovery_cache = data["recovery"]
    _save_session(_session_password, _totp_cache, _passwords_cache, _recovery_cache)
    return True


def _clear_session():
    try:
        os.unlink(SESSION_FILE)
    except FileNotFoundError:
        pass
    except OSError as e:
        print(f"Warning: failed to clear session cache: {e}", file=sys.stderr)


def read_jkey(path: str) -> dict | None:
    if not os.path.exists(path):
        return None
    with _lock_vault(shared=True):
        try:
            with open(path, "r") as f:
                return json.load(f)
        except (json.JSONDecodeError, UnicodeDecodeError, OSError) as e:
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
        tmp = path + ".tmp"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding=encoding, newline=newline) as f:
            f.write(content)
        os.replace(tmp, path)
    else:
        with open(path, "w", encoding=encoding, newline=newline) as f:
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
    return any(os.path.exists(p) for p in (TOTP_FILE, PASSWORDS_FILE, RECOVERY_FILE))


def _decrypt_all(password: str) -> dict[str, dict] | None:
    result: dict[str, dict] = {}
    any_exists = False
    for path, key in ((TOTP_FILE, "totp"), (PASSWORDS_FILE, "passwords"), (RECOVERY_FILE, "recovery")):
        if not os.path.exists(path):
            continue
        any_exists = True
        encrypted = read_jkey(path)
        if encrypted is None:
            return None
        decrypted = aes.decrypt(encrypted, password)
        if decrypted is None:
            return None
        result[key] = decrypted
    return result if any_exists else None


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
    _clear_session()


def encrypt_file(path: str, data: dict, password: str):
    write_jkey(path, aes.encrypt(data, password))


def change_master_password(new_password: str) -> bool:
    global _session_password
    if _session_password is None or _totp_cache is None:
        return False
    totp = _totp_cache
    passwords = _passwords_cache if _passwords_cache is not None else {}
    recovery = _recovery_cache if _recovery_cache is not None else {}
    files = ((TOTP_FILE, totp), (PASSWORDS_FILE, passwords), (RECOVERY_FILE, recovery))
    with _lock_vault():
        staged = []
        try:
            for path, data in files:
                payload = json.dumps(aes.encrypt(data, new_password), indent=4, ensure_ascii=False)
                staged.append((path, _stage_write(path, payload.encode("utf-8"))))
            for path, tmp in staged:
                os.replace(tmp, path)
        except OSError as e:
            for _path, tmp in staged:
                with contextlib.suppress(OSError):
                    os.unlink(tmp)
            raise JkeyError(f"failed to re-encrypt vault: {e}") from e
    _session_password = new_password
    _save_session(new_password, totp, passwords, recovery)
    return True


def load_totp() -> dict:
    ensure_unlocked()
    return _totp_cache or {}


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
    return _passwords_cache or {}


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
    return _recovery_cache or {}


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
    encrypted = aes.encrypt({"raw": encoded}, pw)
    write_jkey(_qr_path(name), encrypted)


def delete_qr_image(name: str) -> bool:
    path = _qr_path(name)
    if not os.path.exists(path):
        return False
    try:
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
    data = aes.decrypt(encrypted, pw)
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
