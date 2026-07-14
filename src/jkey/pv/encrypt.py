import base64
import os
import sys

from jkey import aes
from jkey.pv.core import _ensure_unlocked, _write_jkey, get_session_password


def encrypt_file(input_path: str, output_path: str | None = None):
    if not os.path.exists(input_path):
        print(f"Error: File not found: {input_path}")
        return
    if not _ensure_unlocked():
        return
    password = get_session_password()
    if password is None:
        print("Error: Vault is locked.", file=sys.stderr)
        return
    with open(input_path, "rb") as f:
        raw = f.read()
    encoded = base64.b64encode(raw).decode("ascii")
    encrypted = aes.encrypt({"raw": encoded}, password)
    if output_path is None:
        output_path = input_path + ".jkey"
    _write_jkey(output_path, encrypted)
    print(f"Encrypted: {output_path}")
