import base64
import os

import jkey.pv.core as core
from jkey import aes


def encrypt_file(input_path: str, output_path: str | None = None):
    if not os.path.exists(input_path):
        print(f"Error: File not found: {input_path}")
        return
    if not core._ensure_unlocked():
        return
    with open(input_path, "rb") as f:
        raw = f.read()
    encoded = base64.b64encode(raw).decode("ascii")
    encrypted = aes.encrypt({"raw": encoded}, core._session_password)
    if output_path is None:
        output_path = input_path + ".jkey"
    core._write_jkey(output_path, encrypted)
    print(f"Encrypted: {output_path}")
