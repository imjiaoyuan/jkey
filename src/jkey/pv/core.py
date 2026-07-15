import base64
import contextlib
import json
import os
import platform
import sys
import time

import portalocker

from jkey import aes

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


def _check_password_strength(password: str) -> tuple[bool, str]:
    if len(password) < 8:
        return False, "Password must be at least 8 characters."
    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_special = any(not c.isalnum() for c in password)
    strength_count = sum([has_upper, has_lower, has_digit, has_special])
    if len(password) < 12 and strength_count < 3:
        return False, (
            "Password should be at least 12 characters or include more character types "
            "(upper, lower, digits, special)."
        )
    return True, ""


_SANITIZE_TABLE = str.maketrans({ord(ch): ord("_") for ch in _INVALID_FS_CHARS})


def _sanitize_filename(name: str) -> str:
    return name.translate(_SANITIZE_TABLE)


@contextlib.contextmanager
def _lock_vault(shared: bool = False):
    _ensure_dir()
    mode = portalocker.LOCK_SH if shared else portalocker.LOCK_EX
    with portalocker.Lock(VAULT_LOCK_PATH, "a+", flags=mode) as _fh:
        yield


_session_password: str | None = None
_totp_cache: dict | None = None
_passwords_cache: dict | None = None
_recovery_cache: dict | None = None


def _ensure_dir():
    os.makedirs(CONFIG_DIR, mode=0o700, exist_ok=True)
    os.makedirs(QR_DIR, mode=0o700, exist_ok=True)


def _password_from_env() -> str | None:
    return os.environ.get("JKEY_PASS")


def _prompt_password(prompt: str = "Master password: ") -> str:
    import getpass

    return getpass.getpass(prompt)


def _save_session(password, totp, passwords, recovery):
    _ensure_dir()
    payload = {
        "sv": 3,
        "password": password,
        "totp": totp,
        "passwords": passwords,
        "recovery": recovery,
        "expires": time.time() + SESSION_TIMEOUT,
    }
    try:
        with open(SESSION_FILE, "w") as f:
            json.dump(payload, f)
        os.chmod(SESSION_FILE, 0o600)
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


def _read_jkey(path: str) -> dict | None:
    if not os.path.exists(path):
        return None
    with _lock_vault(shared=True):
        try:
            with open(path, "r") as f:
                return json.load(f)
        except (json.JSONDecodeError, UnicodeDecodeError, OSError) as e:
            print(f"Error: cannot read vault file {path}: {e}", file=sys.stderr)
            return None


def _write_jkey(path: str, encrypted: dict):
    _ensure_dir()
    tmp = path + ".tmp"
    with _lock_vault():
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            json.dump(encrypted, f, indent=4, ensure_ascii=False)
        os.replace(tmp, path)


def _write_secure_text(path: str, content: str, encoding: str = "utf-8", newline: str | None = None):
    with open(path, "w", encoding=encoding, newline=newline) as f:
        f.write(content)
    os.chmod(path, 0o600)


def _write_secure_bytes(path: str, content: bytes):
    with open(path, "wb") as f:
        f.write(content)
    os.chmod(path, 0o600)


def _decrypt_file(path: str, password: str) -> dict | None:
    encrypted = _read_jkey(path)
    if encrypted is None:
        return None
    return aes.decrypt(encrypted, password)


def _encrypt_file(path: str, data: dict, password: str):
    encrypted = aes.encrypt(data, password)
    _write_jkey(path, encrypted)


def _vault_exists() -> bool:
    return any(os.path.exists(p) for p in (TOTP_FILE, PASSWORDS_FILE, RECOVERY_FILE))


def _verify_all_vault_files(password: str) -> bool:
    any_exists = False
    for path in (TOTP_FILE, PASSWORDS_FILE, RECOVERY_FILE):
        if not os.path.exists(path):
            continue
        any_exists = True
        encrypted = _read_jkey(path)
        if encrypted is None:
            return False
        if aes.decrypt(encrypted, password) is None:
            return False
    return any_exists


def _unlock_all(password: str) -> bool:
    global _session_password, _totp_cache, _passwords_cache, _recovery_cache
    totp_data = None
    pw_data = None
    rc_data = None
    any_exists = False
    for path in (TOTP_FILE, PASSWORDS_FILE, RECOVERY_FILE):
        if not os.path.exists(path):
            continue
        any_exists = True
        encrypted = _read_jkey(path)
        if encrypted is None:
            return False
        decrypted = aes.decrypt(encrypted, password)
        if decrypted is None:
            return False
        if path == TOTP_FILE:
            totp_data = decrypted
        elif path == PASSWORDS_FILE:
            pw_data = decrypted
        elif path == RECOVERY_FILE:
            rc_data = decrypted
    if not any_exists:
        return False
    _totp_cache = totp_data or {}
    _passwords_cache = pw_data or {}
    _recovery_cache = rc_data or {}
    _session_password = password
    _save_session(password, _totp_cache, _passwords_cache, _recovery_cache)
    return True


def verify_password(password: str) -> bool:
    return _verify_all_vault_files(password)


def _ensure_unlocked():
    if is_unlocked():
        return True
    if _load_session():
        return True
    if not _vault_exists():
        print("Error: Vault not initialized. Run 'jkey pv init' first.")
        return False
    pw = _password_from_env()
    if pw:
        if _unlock_all(pw):
            return True
        print("Error: JKEY_PASS environment variable contains incorrect password.")
        return False
    for attempt in range(3):
        if attempt > 0:
            time.sleep(2**attempt)
        pw = _prompt_password()
        if _unlock_all(pw):
            return True
        print("Incorrect password. Try again.")
    print("Failed to unlock vault.")
    return False


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


def change_master_password(new_password: str) -> bool:
    global _session_password
    if _session_password is None:
        return False
    totp = _totp_cache
    if totp is None:
        return False
    passwords = _passwords_cache
    recovery = _recovery_cache
    _encrypt_file(TOTP_FILE, totp, new_password)
    _encrypt_file(PASSWORDS_FILE, passwords if passwords is not None else {}, new_password)
    _encrypt_file(RECOVERY_FILE, recovery if recovery is not None else {}, new_password)
    _session_password = new_password
    _save_session(new_password, totp, passwords, recovery)
    return True


def load_totp() -> dict | None:
    if not _ensure_unlocked():
        return None
    return _totp_cache


def save_totp(data: dict):
    global _totp_cache
    pw = _session_password
    if pw is None:
        print("Warning: vault is locked. Changes not saved.", file=sys.stderr)
        return
    _encrypt_file(TOTP_FILE, data, pw)
    _totp_cache = data
    _save_session(pw, data, _passwords_cache, _recovery_cache)


def load_passwords() -> dict | None:
    if not _ensure_unlocked():
        return None
    return _passwords_cache


def save_passwords(data: dict):
    global _passwords_cache
    pw = _session_password
    if pw is None:
        print("Warning: vault is locked. Changes not saved.", file=sys.stderr)
        return
    _encrypt_file(PASSWORDS_FILE, data, pw)
    _passwords_cache = data
    _save_session(pw, _totp_cache, data, _recovery_cache)


def load_recovery() -> dict | None:
    if not _ensure_unlocked():
        return None
    return _recovery_cache


def save_recovery(data: dict):
    global _recovery_cache
    pw = _session_password
    if pw is None:
        print("Warning: vault is locked. Changes not saved.", file=sys.stderr)
        return
    _encrypt_file(RECOVERY_FILE, data, pw)
    _recovery_cache = data
    _save_session(pw, _totp_cache, _passwords_cache, data)


def _qr_path(name: str) -> str:
    return os.path.join(QR_DIR, f"{_sanitize_filename(name)}{_JKEY_EXT}")


def save_qr_image(name: str, image_data: bytes):
    pw = _session_password
    if pw is None:
        print("Warning: vault is locked. Changes not saved.", file=sys.stderr)
        return
    _ensure_dir()
    encoded = base64.b64encode(image_data).decode("ascii")
    encrypted = aes.encrypt({"raw": encoded}, pw)
    _write_jkey(_qr_path(name), encrypted)


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
    if not _ensure_unlocked():
        return None
    pw = _session_password
    if pw is None:
        return None
    path = _qr_path(name)
    if not os.path.exists(path):
        legacy = os.path.join(QR_DIR, f"{name}{_JKEY_EXT}")
        if not os.path.exists(legacy):
            return None
        path = legacy
    encrypted = _read_jkey(path)
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
