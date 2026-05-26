import base64
import hashlib
import json
import os
import platform
import sys
import time

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
SESSION_TIMEOUT = 300

_INVALID_FS_CHARS = '<>:"/\\|?*'


def _sanitize_filename(name: str) -> str:
    for ch in _INVALID_FS_CHARS:
        name = name.replace(ch, "_")
    return name

_session_password: str | None = None
_totp_cache: dict | None = None
_passwords_cache: dict | None = None
_recovery_cache: dict | None = None


def _session_secret(password: str) -> str:
    material = f"jkey-session-v1:{password}"
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


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
        "expires": time.time() + SESSION_TIMEOUT,
        "password": password,
        "totp": totp,
        "passwords": passwords,
        "recovery": recovery,
    }
    try:
        with open(SESSION_FILE, "w") as f:
            json.dump({"session": aes.encrypt(payload, _session_secret(password))}, f)
        os.chmod(SESSION_FILE, 0o600)
    except OSError as e:
        print(f"Warning: failed to save session cache: {e}", file=sys.stderr)


def _load_session(password: str) -> bool:
    global _session_password, _totp_cache, _passwords_cache, _recovery_cache
    try:
        with open(SESSION_FILE) as f:
            raw = json.load(f)
        if isinstance(raw, dict) and "session" in raw:
            data = aes.decrypt(raw["session"], _session_secret(password))
            if data is None:
                _clear_session()
                return False
        else:
            data = raw
        if time.time() >= data["expires"]:
            os.unlink(SESSION_FILE)
            return False
        stored_password = data["password"]
        if stored_password != password:
            _clear_session()
            return False
        totp = _decrypt_file(TOTP_FILE, password)
        if totp is None:
            _clear_session()
            return False
        _session_password = password
        _totp_cache = totp
        _passwords_cache = _decrypt_file(PASSWORDS_FILE, password) or {}
        _recovery_cache = _decrypt_file(RECOVERY_FILE, password) or {}
        return True
    except (OSError, json.JSONDecodeError, KeyError, TypeError):
        return False


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
    try:
        with open(path, "r") as f:
            return json.load(f)
    except Exception:
        return None


def _write_jkey(path: str, encrypted: dict):
    _ensure_dir()
    tmp = path + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(encrypted, f, indent=4, ensure_ascii=False)
    os.replace(tmp, path)


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


def _decrypt_any_vault_file(password: str) -> bool:
    for path in (TOTP_FILE, PASSWORDS_FILE, RECOVERY_FILE):
        if os.path.exists(path):
            if _decrypt_file(path, password) is not None:
                return True
    return False


def _unlock_all(password: str) -> bool:
    global _session_password, _totp_cache, _passwords_cache, _recovery_cache
    if not _decrypt_any_vault_file(password):
        return False
    _totp_cache = _decrypt_file(TOTP_FILE, password) or {}
    _passwords_cache = _decrypt_file(PASSWORDS_FILE, password) or {}
    _recovery_cache = _decrypt_file(RECOVERY_FILE, password) or {}
    _session_password = password
    _save_session(password, _totp_cache, _passwords_cache, _recovery_cache)
    return True


def verify_password(password: str) -> bool:
    return _decrypt_any_vault_file(password)


def _ensure_unlocked():
    if is_unlocked():
        return True
    if not _vault_exists():
        print("Error: Vault not initialized. Run 'jkey pv init' first.")
        return False
    pw = _password_from_env()
    if pw:
        if _load_session(pw):
            return True
        if _unlock_all(pw):
            return True
        print("Error: JKEY_PASS environment variable contains incorrect password.")
        return False
    for attempt in range(3):
        if attempt > 0:
            time.sleep(2 ** attempt)
        pw = _prompt_password()
        if _load_session(pw):
            return True
        if _unlock_all(pw):
            return True
        print("Incorrect password. Try again.")
    print("Failed to unlock vault.")
    return False


def is_unlocked() -> bool:
    return _session_password is not None


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
        return
    _encrypt_file(TOTP_FILE, data, pw)
    _totp_cache = data
    _save_session(pw, data, _passwords_cache, _recovery_cache)


def load_passwords() -> dict | None:
    if not _ensure_unlocked():
        return None
    global _passwords_cache
    if _passwords_cache is None and _session_password is not None:
        _passwords_cache = _decrypt_file(PASSWORDS_FILE, _session_password) or {}
    return _passwords_cache


def save_passwords(data: dict):
    global _passwords_cache
    pw = _session_password
    if pw is None:
        return
    _encrypt_file(PASSWORDS_FILE, data, pw)
    _passwords_cache = data
    _save_session(pw, _totp_cache, data, _recovery_cache)


def load_recovery() -> dict | None:
    if not _ensure_unlocked():
        return None
    global _recovery_cache
    if _recovery_cache is None and _session_password is not None:
        _recovery_cache = _decrypt_file(RECOVERY_FILE, _session_password) or {}
    return _recovery_cache


def save_recovery(data: dict):
    global _recovery_cache
    pw = _session_password
    if pw is None:
        return
    _encrypt_file(RECOVERY_FILE, data, pw)
    _recovery_cache = data
    _save_session(pw, _totp_cache, _passwords_cache, data)


def _qr_path(name: str) -> str:
    return os.path.join(QR_DIR, f"{_sanitize_filename(name)}.jkey")


def save_qr_image(name: str, image_data: bytes):
    pw = _session_password
    if pw is None:
        return
    _ensure_dir()
    encoded = base64.b64encode(image_data).decode("ascii")
    encrypted = aes.encrypt({"raw": encoded}, pw)
    _write_jkey(_qr_path(name), encrypted)


def load_qr_image(name: str) -> bytes | None:
    if not _ensure_unlocked():
        return None
    pw = _session_password
    if pw is None:
        return None
    path = _qr_path(name)
    if not os.path.exists(path):
        legacy = os.path.join(QR_DIR, f"{name}.jkey")
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
        if f.endswith(".jkey"):
            names.append(f[:-5])
    return sorted(names)
