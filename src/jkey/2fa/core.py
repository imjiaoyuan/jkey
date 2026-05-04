import base64
import hashlib
import hmac
import os
import struct
import time

from jkey.pv.core import load_recovery, save_recovery


def _hotp(secret: bytes, counter: int, digits: int = 6) -> str:
    msg = struct.pack(">Q", counter)
    h = hmac.new(secret, msg, hashlib.sha1).digest()
    offset = h[-1] & 0xf
    truncated = struct.unpack(">I", h[offset:offset+4])[0] & 0x7fffffff
    return str(truncated % (10 ** digits)).zfill(digits)


def _b32_decode(s: str) -> bytes:
    s = s.upper().replace(" ", "")
    remainder = len(s) % 8
    if remainder:
        s += "=" * (8 - remainder)
    return base64.b32decode(s)


def _validate_b32_secret(s: str) -> bool:
    try:
        _b32_decode(s)
        return True
    except Exception:
        return False


def totp(secret_key: str, digits: int = 6, interval: int = 30) -> str:
    secret = _b32_decode(secret_key)
    counter = int(time.time()) // interval
    return _hotp(secret, counter, digits)


def _import_recovery_file(account: str, recovery_path: str | None):
    if not recovery_path:
        return
    if not os.path.exists(recovery_path):
        print(f"Warning: Recovery file not found: {recovery_path}")
        return
    try:
        with open(recovery_path, "r", encoding="utf-8") as f:
            codes = [line.strip() for line in f if line.strip()]
        if codes:
            data = load_recovery()
            if data is None:
                return
            data[account] = codes
            save_recovery(data)
            print(f"Imported {len(codes)} recovery codes for {account}")
    except OSError as e:
        print(f"Warning: Could not read recovery file: {e}")
