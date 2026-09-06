import base64
import json
import os

from jkey import aes
from jkey.errors import JkeyError
from jkey.pv.core import ensure_unlocked, get_session_password, read_jkey


def decrypt_file(path: str, output_path: str | None = None):
    if not os.path.exists(path):
        raise JkeyError(f"File not found: {path}")
    ensure_unlocked()
    password = get_session_password()
    if password is None:
        raise JkeyError("Vault is locked.")
    encrypted = read_jkey(path)
    if encrypted is None:
        raise JkeyError(f"File not found: {path}")
    data = aes.decrypt(encrypted, password)
    if data is None:
        raise JkeyError("Decryption failed.")
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
            try:
                print(raw.decode("utf-8"))
            except UnicodeDecodeError:
                raise JkeyError("Decrypted data is not valid UTF-8 text; use -o <file> to save.") from None
