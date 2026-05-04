import base64
import json
import os
import time

from jkey import aes

CONFIG_DIR = os.path.join(os.path.expanduser("~"), ".config", "jkey")
TOTP_FILE = os.path.join(CONFIG_DIR, "totp.jkey")
PASSWORDS_FILE = os.path.join(CONFIG_DIR, "passwords.jkey")
RECOVERY_FILE = os.path.join(CONFIG_DIR, "recovery.jkey")
QR_DIR = os.path.join(CONFIG_DIR, "qr")
SESSION_FILE = os.path.join(CONFIG_DIR, ".session")
SESSION_TIMEOUT = 300

_session_password: str | None = None
_totp_cache: dict | None = None
_passwords_cache: dict | None = None
_recovery_cache: dict | None = None


def _ensure_dir():
    os.makedirs(CONFIG_DIR, exist_ok=True)
    os.makedirs(QR_DIR, exist_ok=True)


def _password_from_env() -> str | None:
    return os.environ.get("JKEY_PASS")


def _prompt_password(prompt: str = "Master password: ") -> str:
    import getpass
    return getpass.getpass(prompt)


def _save_session(password, totp, passwords, recovery):
    _ensure_dir()
    try:
        with open(SESSION_FILE, "w") as f:
            json.dump({
                "expires": time.time() + SESSION_TIMEOUT,
                "password": password,
                "totp": totp,
                "passwords": passwords,
                "recovery": recovery,
            }, f)
        os.chmod(SESSION_FILE, 0o600)
    except OSError:
        pass


def _load_session() -> bool:
    global _session_password, _totp_cache, _passwords_cache, _recovery_cache
    try:
        with open(SESSION_FILE) as f:
            data = json.load(f)
        if time.time() >= data["expires"]:
            os.unlink(SESSION_FILE)
            return False
        _session_password = data["password"]
        _totp_cache = data.get("totp", {})
        _passwords_cache = data.get("passwords", {})
        _recovery_cache = data.get("recovery", {})
        return True
    except (OSError, json.JSONDecodeError, KeyError, TypeError):
        return False


def _clear_session():
    try:
        os.unlink(SESSION_FILE)
    except OSError:
        pass


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
    with open(tmp, "w") as f:
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


def _unlock_all(password: str) -> bool:
    global _session_password, _totp_cache, _passwords_cache, _recovery_cache
    data = _decrypt_file(TOTP_FILE, password)
    if data is None:
        return False
    _totp_cache = data
    _passwords_cache = _decrypt_file(PASSWORDS_FILE, password) or {}
    _recovery_cache = _decrypt_file(RECOVERY_FILE, password) or {}
    _session_password = password
    _save_session(password, data, _passwords_cache, _recovery_cache)
    return True


def verify_password(password: str) -> bool:
    encrypted = _read_jkey(TOTP_FILE)
    if encrypted is None:
        return False
    return aes.decrypt(encrypted, password) is not None


def _ensure_unlocked():
    if is_unlocked():
        return True
    if not os.path.exists(TOTP_FILE):
        print("Error: Vault not initialized. Run 'jkey pv init' first.")
        return False
    if _load_session():
        return True
    pw = _password_from_env()
    if pw and _unlock_all(pw):
        return True
    for _ in range(3):
        pw = _prompt_password()
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
    """Re-encrypt all vault data with a new master password."""
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


def save_qr_image(name: str, image_data: bytes):
    pw = _session_password
    if pw is None:
        return
    _ensure_dir()
    encoded = base64.b64encode(image_data).decode("ascii")
    encrypted = aes.encrypt({"raw": encoded}, pw)
    path = os.path.join(QR_DIR, f"{name}.jkey")
    _write_jkey(path, encrypted)


def load_qr_image(name: str) -> bytes | None:
    if not _ensure_unlocked():
        return None
    pw = _session_password
    if pw is None:
        return None
    path = os.path.join(QR_DIR, f"{name}.jkey")
    if not os.path.exists(path):
        return None
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
