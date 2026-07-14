import base64
import json
import os
import sys

from jkey import aes
from jkey.pv.core import _ensure_unlocked, _read_jkey, get_session_password


def decrypt_file(path: str, output_path: str | None = None):
    if not os.path.exists(path):
        print(f"Error: File not found: {path}")
        return
    if not _ensure_unlocked():
        return
    password = get_session_password()
    if password is None:
        print("Error: Vault is locked.", file=sys.stderr)
        return
    encrypted = _read_jkey(path)
    if encrypted is None:
        return
    data = aes.decrypt(encrypted, password)
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
