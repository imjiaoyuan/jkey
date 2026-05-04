import json
import os
import getpass
import base64

from jkey import aes

CONFIG_DIR = os.path.join(os.path.expanduser("~"), ".config", "jkey")
TOTP_FILE = os.path.join(CONFIG_DIR, "totp.jkey")
PASSWORDS_FILE = os.path.join(CONFIG_DIR, "passwords.jkey")
RECOVERY_FILE = os.path.join(CONFIG_DIR, "recovery.jkey")
QR_DIR = os.path.join(CONFIG_DIR, "qr")

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
    return getpass.getpass(prompt)


def _read_jkey(path: str) -> dict | None:
    if not os.path.exists(path):
        return None
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def _write_jkey(path: str, encrypted: dict):
    _ensure_dir()
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
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


# ── Per-type load/save ──


def load_totp() -> dict | None:
    if not _ensure_unlocked():
        return None
    return _totp_cache


def save_totp(data: dict):
    global _totp_cache
    if _session_password is None:
        return
    _encrypt_file(TOTP_FILE, data, _session_password)
    _totp_cache = data


def load_passwords() -> dict | None:
    if not _ensure_unlocked():
        return None
    return _passwords_cache


def save_passwords(data: dict):
    global _passwords_cache
    if _session_password is None:
        return
    _encrypt_file(PASSWORDS_FILE, data, _session_password)
    _passwords_cache = data


def load_recovery() -> dict | None:
    if not _ensure_unlocked():
        return None
    return _recovery_cache


def save_recovery(data: dict):
    global _recovery_cache
    if _session_password is None:
        return
    _encrypt_file(RECOVERY_FILE, data, _session_password)
    _recovery_cache = data


# ── QR image storage ──


def save_qr_image(name: str, image_data: bytes):
    if _session_password is None:
        return
    _ensure_dir()
    encoded = base64.b64encode(image_data).decode("ascii")
    encrypted = aes.encrypt({"raw": encoded}, _session_password)
    path = os.path.join(QR_DIR, f"{name}.jkey")
    _write_jkey(path, encrypted)


def load_qr_image(name: str) -> bytes | None:
    if not _ensure_unlocked():
        return None
    path = os.path.join(QR_DIR, f"{name}.jkey")
    if not os.path.exists(path):
        return None
    encrypted = _read_jkey(path)
    if encrypted is None:
        return None
    data = aes.decrypt(encrypted, _session_password)
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


# ── Encrypt/Decrypt any file ──


def encrypt_file(input_path: str, output_path: str | None = None):
    if not os.path.exists(input_path):
        print(f"Error: File not found: {input_path}")
        return
    if not _ensure_unlocked():
        return
    with open(input_path, "rb") as f:
        raw = f.read()
    encoded = base64.b64encode(raw).decode("ascii")
    encrypted = aes.encrypt({"raw": encoded}, _session_password)
    if output_path is None:
        output_path = input_path + ".jkey"
    _write_jkey(output_path, encrypted)
    print(f"Encrypted: {output_path}")


def decrypt_file(path: str, output_path: str | None = None):
    if not os.path.exists(path):
        print(f"Error: File not found: {path}")
        return
    if not _ensure_unlocked():
        return
    encrypted = _read_jkey(path)
    if encrypted is None:
        return
    data = aes.decrypt(encrypted, _session_password)
    if data is None:
        print("Error: Decryption failed.")
        return
    if "raw" in data:
        raw = base64.b64decode(data["raw"])
    else:
        raw = json.dumps(data, indent=4, ensure_ascii=False).encode("utf-8")
    if output_path:
        with open(output_path, "wb") as f:
            f.write(raw)
        print(f"Decrypted: {output_path}")
    else:
        if "raw" in data:
            print("(binary data, use -o <file> to save)")
        else:
            print(raw.decode("utf-8"))


# ── Commands ──


def cmd_init():
    if os.path.exists(TOTP_FILE):
        print("Vault already exists. Use 'jkey pv set-pw' to change password.")
        return
    pw1 = _password_from_env()
    if pw1 is None:
        pw1 = _prompt_password("Set master password: ")
        if not pw1:
            print("Password cannot be empty.")
            return
        pw2 = _prompt_password("Confirm master password: ")
        if pw1 != pw2:
            print("Passwords do not match.")
            return
    _ensure_dir()
    _encrypt_file(TOTP_FILE, {}, pw1)
    _encrypt_file(PASSWORDS_FILE, {}, pw1)
    _encrypt_file(RECOVERY_FILE, {}, pw1)
    _unlock_all(pw1)
    print(f"Vault initialized at {CONFIG_DIR}")


def cmd_unlock():
    if is_unlocked():
        print("Vault is already unlocked.")
        return
    if not os.path.exists(TOTP_FILE):
        print("Error: Vault not initialized. Run 'jkey pv init' first.")
        return
    if _ensure_unlocked():
        print("Vault unlocked.")


def cmd_lock():
    if not is_unlocked():
        print("Vault is already locked.")
        return
    lock()
    print("Vault locked.")


def cmd_set_pw():
    if not os.path.exists(TOTP_FILE):
        print("Error: Vault not initialized. Run 'jkey pv init' first.")
        return
    if not _ensure_unlocked():
        return
    pw1 = _prompt_password("New master password: ")
    if not pw1:
        print("Password cannot be empty.")
        return
    pw2 = _prompt_password("Confirm new master password: ")
    if pw1 != pw2:
        print("Passwords do not match.")
        return
    global _session_password
    _encrypt_file(TOTP_FILE, _totp_cache, pw1)
    _encrypt_file(PASSWORDS_FILE, _passwords_cache, pw1)
    _encrypt_file(RECOVERY_FILE, _recovery_cache, pw1)
    _session_password = pw1
    print("Master password changed.")
