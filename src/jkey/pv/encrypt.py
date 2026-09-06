import base64
import os

from jkey import aes
from jkey.errors import JkeyError
from jkey.pv.core import ensure_unlocked, get_session_password, write_jkey


def encrypt_file(input_path: str, output_path: str | None = None):
    if not os.path.exists(input_path):
        raise JkeyError(f"File not found: {input_path}")
    ensure_unlocked()
    password = get_session_password()
    if password is None:
        raise JkeyError("Vault is locked.")
    try:
        with open(input_path, "rb") as f:
            raw = f.read()
    except OSError as e:
        raise JkeyError(f"Cannot read '{input_path}': {e}") from e
    encoded = base64.b64encode(raw).decode("ascii")
    encrypted = aes.encrypt({"raw": encoded}, password)
    if output_path is None:
        output_path = input_path + ".jkey"
    write_jkey(output_path, encrypted)
    print(f"Encrypted: {output_path}")
