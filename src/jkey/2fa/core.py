import base64
import binascii
import hashlib
import hmac
import struct
import time


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
    except (binascii.Error, ValueError):
        return False


def totp(secret_key: str, digits: int = 6, interval: int = 30) -> str:
    secret = _b32_decode(secret_key)
    counter = int(time.time()) // interval
    return _hotp(secret, counter, digits)
