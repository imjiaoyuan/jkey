import base64
import json
import os

from jkey import aes
from jkey.errors import JkeyError
from jkey.pv import core


def encrypt_file(input_path: str, output_path: str | None = None, json_data: bool = False):
    if not os.path.exists(input_path):
        raise JkeyError(f"File not found: {input_path}")
    try:
        with open(input_path, "rb") as f:
            raw = f.read()
    except OSError as e:
        raise JkeyError(f"Cannot read '{input_path}': {e}") from e
    if json_data:
        try:
            data = json.loads(raw)
        except (ValueError, UnicodeError) as e:
            raise JkeyError(f"Invalid JSON: {e}") from e
        if not isinstance(data, dict):
            raise JkeyError("Vault JSON must be an object.")
        password = core.password_from_env() or core.get_session_password() or core.prompt_password("File password: ")
    else:
        core.ensure_unlocked()
        password = core.get_session_password()
        data = {"raw": base64.b64encode(raw).decode("ascii")}
    if not password:
        raise JkeyError("Cancelled.")
    encrypted = aes.encrypt(data, password)
    if output_path is None:
        output_path = input_path + ".jkey"
    # Preserve an existing encrypted file if a manually merged version replaces it.
    output_path = os.path.abspath(output_path)
    with core._lock_vault():
        payload = json.dumps(encrypted, indent=4, ensure_ascii=False).encode()
        saved = core.transaction.preserve_and_write(output_path, payload)
        if saved:
            print(f"Kept previous file: {saved}")
        if output_path in (core.TOTP_FILE, core.PASSWORDS_FILE, core.RECOVERY_FILE) or (
            os.path.dirname(output_path) == core.QR_DIR
        ):
            core.lock()
    print(f"Encrypted: {output_path}")
