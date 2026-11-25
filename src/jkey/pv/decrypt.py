import base64
import json
import os

from jkey import aes
from jkey.errors import JkeyError
from jkey.pv import core


def decrypt_file(path: str, output_path: str | None = None):
    if not os.path.exists(path):
        raise JkeyError(f"File not found: {path}")
    try:
        with open(path, encoding="utf-8") as f:
            encrypted = json.load(f)
    except (OSError, ValueError) as e:
        raise JkeyError(f"Cannot read encrypted file: {e}") from e
    password = core.password_from_env() or core.get_session_password()
    data = aes.decrypt(encrypted, password) if password else None
    if data is None and not core.password_from_env():
        password = core.prompt_password("File password: ")
        data = aes.decrypt(encrypted, password) if password else None
    if data is None:
        raise JkeyError("Decryption failed.")
    if "raw" in data:
        raw = base64.b64decode(data["raw"])
    else:
        raw = json.dumps(data, indent=4, ensure_ascii=False).encode("utf-8")
    if output_path:
        core.write_secure_bytes(os.path.abspath(output_path), raw, atomic=True)
        print(f"Decrypted: {output_path}")
    else:
        if "raw" in data:
            print("(binary data, use -o <file> to save)")
        else:
            print(raw.decode("utf-8"))
