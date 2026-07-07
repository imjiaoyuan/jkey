import base64
import binascii
import hashlib
import hmac
import json
import os
import sys

SBOX = [
    0x63,
    0x7C,
    0x77,
    0x7B,
    0xF2,
    0x6B,
    0x6F,
    0xC5,
    0x30,
    0x01,
    0x67,
    0x2B,
    0xFE,
    0xD7,
    0xAB,
    0x76,
    0xCA,
    0x82,
    0xC9,
    0x7D,
    0xFA,
    0x59,
    0x47,
    0xF0,
    0xAD,
    0xD4,
    0xA2,
    0xAF,
    0x9C,
    0xA4,
    0x72,
    0xC0,
    0xB7,
    0xFD,
    0x93,
    0x26,
    0x36,
    0x3F,
    0xF7,
    0xCC,
    0x34,
    0xA5,
    0xE5,
    0xF1,
    0x71,
    0xD8,
    0x31,
    0x15,
    0x04,
    0xC7,
    0x23,
    0xC3,
    0x18,
    0x96,
    0x05,
    0x9A,
    0x07,
    0x12,
    0x80,
    0xE2,
    0xEB,
    0x27,
    0xB2,
    0x75,
    0x09,
    0x83,
    0x2C,
    0x1A,
    0x1B,
    0x6E,
    0x5A,
    0xA0,
    0x52,
    0x3B,
    0xD6,
    0xB3,
    0x29,
    0xE3,
    0x2F,
    0x84,
    0x53,
    0xD1,
    0x00,
    0xED,
    0x20,
    0xFC,
    0xB1,
    0x5B,
    0x6A,
    0xCB,
    0xBE,
    0x39,
    0x4A,
    0x4C,
    0x58,
    0xCF,
    0xD0,
    0xEF,
    0xAA,
    0xFB,
    0x43,
    0x4D,
    0x33,
    0x85,
    0x45,
    0xF9,
    0x02,
    0x7F,
    0x50,
    0x3C,
    0x9F,
    0xA8,
    0x51,
    0xA3,
    0x40,
    0x8F,
    0x92,
    0x9D,
    0x38,
    0xF5,
    0xBC,
    0xB6,
    0xDA,
    0x21,
    0x10,
    0xFF,
    0xF3,
    0xD2,
    0xCD,
    0x0C,
    0x13,
    0xEC,
    0x5F,
    0x97,
    0x44,
    0x17,
    0xC4,
    0xA7,
    0x7E,
    0x3D,
    0x64,
    0x5D,
    0x19,
    0x73,
    0x60,
    0x81,
    0x4F,
    0xDC,
    0x22,
    0x2A,
    0x90,
    0x88,
    0x46,
    0xEE,
    0xB8,
    0x14,
    0xDE,
    0x5E,
    0x0B,
    0xDB,
    0xE0,
    0x32,
    0x3A,
    0x0A,
    0x49,
    0x06,
    0x24,
    0x5C,
    0xC2,
    0xD3,
    0xAC,
    0x62,
    0x91,
    0x95,
    0xE4,
    0x79,
    0xE7,
    0xC8,
    0x37,
    0x6D,
    0x8D,
    0xD5,
    0x4E,
    0xA9,
    0x6C,
    0x56,
    0xF4,
    0xEA,
    0x65,
    0x7A,
    0xAE,
    0x08,
    0xBA,
    0x78,
    0x25,
    0x2E,
    0x1C,
    0xA6,
    0xB4,
    0xC6,
    0xE8,
    0xDD,
    0x74,
    0x1F,
    0x4B,
    0xBD,
    0x8B,
    0x8A,
    0x70,
    0x3E,
    0xB5,
    0x66,
    0x48,
    0x03,
    0xF6,
    0x0E,
    0x61,
    0x35,
    0x57,
    0xB9,
    0x86,
    0xC1,
    0x1D,
    0x9E,
    0xE1,
    0xF8,
    0x98,
    0x11,
    0x69,
    0xD9,
    0x8E,
    0x94,
    0x9B,
    0x1E,
    0x87,
    0xE9,
    0xCE,
    0x55,
    0x28,
    0xDF,
    0x8C,
    0xA1,
    0x89,
    0x0D,
    0xBF,
    0xE6,
    0x42,
    0x68,
    0x41,
    0x99,
    0x2D,
    0x0F,
    0xB0,
    0x54,
    0xBB,
    0x16,
]

INV_SBOX = [0] * 256
for _i, _v in enumerate(SBOX):
    INV_SBOX[_v] = _i

RCON = [0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]


def _xtime(a):
    return ((a << 1) ^ 0x11B) & 0xFF if a & 0x80 else (a << 1) & 0xFF


def _gf_mul(a, b):
    result = 0
    for _ in range(8):
        if b & 1:
            result ^= a
        a = _xtime(a)
        b >>= 1
    return result


def _sub_word(word):
    return (
        (SBOX[(word >> 24) & 0xFF] << 24)
        | (SBOX[(word >> 16) & 0xFF] << 16)
        | (SBOX[(word >> 8) & 0xFF] << 8)
        | SBOX[word & 0xFF]
    )


def _rot_word(word):
    return ((word << 8) | (word >> 24)) & 0xFFFFFFFF


def _key_expansion(key: bytes) -> list:
    nr = 14
    nk = 8
    nb = 4
    nw = nb * (nr + 1)
    w = []
    for i in range(nk):
        w.append(int.from_bytes(key[4 * i : 4 * i + 4], "big"))
    for i in range(nk, nw):
        temp = w[i - 1]
        if i % nk == 0:
            temp = _sub_word(_rot_word(temp)) ^ (RCON[i // nk] << 24)
        elif i % nk == 4:
            temp = _sub_word(temp)
        w.append(w[i - nk] ^ temp)
    return w


def _bytes_to_state(b: bytes):
    return [list(b[i : i + 4]) for i in range(0, 16, 4)]


def _state_to_bytes(state):
    result = bytearray()
    for row in state:
        result.extend(row)
    return bytes(result)


def _add_round_key(state, rk):
    rk_bytes = []
    for word in rk:
        rk_bytes.extend([(word >> 24) & 0xFF, (word >> 16) & 0xFF, (word >> 8) & 0xFF, word & 0xFF])
    for i in range(4):
        for j in range(4):
            state[j][i] ^= rk_bytes[i * 4 + j]


def _sub_bytes(state):
    for i in range(4):
        for j in range(4):
            state[i][j] = SBOX[state[i][j]]


def _inv_sub_bytes(state):
    for i in range(4):
        for j in range(4):
            state[i][j] = INV_SBOX[state[i][j]]


def _shift_rows(state):
    state[1][0], state[1][1], state[1][2], state[1][3] = state[1][1], state[1][2], state[1][3], state[1][0]
    state[2][0], state[2][1], state[2][2], state[2][3] = state[2][2], state[2][3], state[2][0], state[2][1]
    state[3][0], state[3][1], state[3][2], state[3][3] = state[3][3], state[3][0], state[3][1], state[3][2]


def _inv_shift_rows(state):
    state[1][0], state[1][1], state[1][2], state[1][3] = state[1][3], state[1][0], state[1][1], state[1][2]
    state[2][0], state[2][1], state[2][2], state[2][3] = state[2][2], state[2][3], state[2][0], state[2][1]
    state[3][0], state[3][1], state[3][2], state[3][3] = state[3][1], state[3][2], state[3][3], state[3][0]


def _mix_columns(state):
    for i in range(4):
        a = [state[j][i] for j in range(4)]
        state[0][i] = _gf_mul(2, a[0]) ^ _gf_mul(3, a[1]) ^ a[2] ^ a[3]
        state[1][i] = a[0] ^ _gf_mul(2, a[1]) ^ _gf_mul(3, a[2]) ^ a[3]
        state[2][i] = a[0] ^ a[1] ^ _gf_mul(2, a[2]) ^ _gf_mul(3, a[3])
        state[3][i] = _gf_mul(3, a[0]) ^ a[1] ^ a[2] ^ _gf_mul(2, a[3])


def _inv_mix_columns(state):
    for i in range(4):
        a = [state[j][i] for j in range(4)]
        state[0][i] = _gf_mul(14, a[0]) ^ _gf_mul(11, a[1]) ^ _gf_mul(13, a[2]) ^ _gf_mul(9, a[3])
        state[1][i] = _gf_mul(9, a[0]) ^ _gf_mul(14, a[1]) ^ _gf_mul(11, a[2]) ^ _gf_mul(13, a[3])
        state[2][i] = _gf_mul(13, a[0]) ^ _gf_mul(9, a[1]) ^ _gf_mul(14, a[2]) ^ _gf_mul(11, a[3])
        state[3][i] = _gf_mul(11, a[0]) ^ _gf_mul(13, a[1]) ^ _gf_mul(9, a[2]) ^ _gf_mul(14, a[3])


def _encrypt_block(block: bytes, w: list) -> bytes:
    state = _bytes_to_state(block)
    rk = w[:4]
    _add_round_key(state, rk)
    for rnd in range(1, 14):
        _sub_bytes(state)
        _shift_rows(state)
        _mix_columns(state)
        rk = w[4 * rnd : 4 * (rnd + 1)]
        _add_round_key(state, rk)
    _sub_bytes(state)
    _shift_rows(state)
    rk = w[56:60]
    _add_round_key(state, rk)
    return _state_to_bytes(state)


def _decrypt_block(block: bytes, w: list) -> bytes:
    state = _bytes_to_state(block)
    rk = w[56:60]
    _add_round_key(state, rk)
    _inv_shift_rows(state)
    _inv_sub_bytes(state)
    for rnd in range(13, 0, -1):
        rk = w[4 * rnd : 4 * (rnd + 1)]
        _add_round_key(state, rk)
        _inv_mix_columns(state)
        _inv_shift_rows(state)
        _inv_sub_bytes(state)
    rk = w[:4]
    _add_round_key(state, rk)
    return _state_to_bytes(state)


def _pkcs7_pad(data: bytes, block_size: int = 16) -> bytes:
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len] * pad_len)


def _pkcs7_unpad(data: bytes) -> bytes:
    pad_len = data[-1]
    if pad_len < 1 or pad_len > 16:
        raise ValueError("Invalid padding")
    for b in data[-pad_len:]:
        if b != pad_len:
            raise ValueError("Invalid padding")
    return data[:-pad_len]


def aes_cbc_encrypt(plaintext: bytes, key: bytes, iv: bytes) -> bytes:
    w = _key_expansion(key)
    ciphertext = bytearray()
    prev = iv
    for i in range(0, len(plaintext), 16):
        block = plaintext[i : i + 16]
        xored = bytes(a ^ b for a, b in zip(block, prev))
        enc = _encrypt_block(xored, w)
        ciphertext.extend(enc)
        prev = enc
    return bytes(ciphertext)


def aes_cbc_decrypt(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    w = _key_expansion(key)
    plaintext = bytearray()
    prev = iv
    for i in range(0, len(ciphertext), 16):
        block = ciphertext[i : i + 16]
        dec = _decrypt_block(block, w)
        xored = bytes(a ^ b for a, b in zip(dec, prev))
        plaintext.extend(xored)
        prev = block
    return bytes(plaintext)


PBKDF2_ITERATIONS = 600_000
SALT_LENGTH = 16
IV_LENGTH = 16
KEY_LENGTH = 32


def derive_key(password: str, salt: bytes, dklen: int = KEY_LENGTH) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ITERATIONS, dklen=dklen)


def encrypt(data: dict, password: str) -> dict:
    salt = os.urandom(SALT_LENGTH)
    iv = os.urandom(IV_LENGTH)
    derived = derive_key(password, salt, dklen=64)
    enc_key = derived[:32]
    mac_key = derived[32:]
    plaintext = json.dumps(data, ensure_ascii=False).encode("utf-8")
    padded = _pkcs7_pad(plaintext)
    ciphertext = aes_cbc_encrypt(padded, enc_key, iv)
    mac = hmac.new(mac_key, iv + ciphertext, hashlib.sha256).digest()
    return {
        "salt": base64.b64encode(salt).decode("ascii"),
        "iv": base64.b64encode(iv).decode("ascii"),
        "data": base64.b64encode(ciphertext).decode("ascii"),
        "mac": base64.b64encode(mac).decode("ascii"),
        "version": 3,
    }


def decrypt(encrypted: dict, password: str) -> dict | None:
    try:
        salt = base64.b64decode(encrypted["salt"])
        iv = base64.b64decode(encrypted["iv"])
        ciphertext = base64.b64decode(encrypted["data"])
        stored_mac = base64.b64decode(encrypted["mac"])
    except (KeyError, TypeError, binascii.Error):
        return None

    version = encrypted.get("version", 1)
    if version >= 3:
        derived = derive_key(password, salt, dklen=64)
        enc_key = derived[:32]
        mac_key = derived[32:]
    else:
        enc_key = derive_key(password, salt)
        mac_key = enc_key

    expected_mac = hmac.new(mac_key, iv + ciphertext, hashlib.sha256).digest()
    if not hmac.compare_digest(stored_mac, expected_mac):
        return None

    try:
        padded = aes_cbc_decrypt(ciphertext, enc_key, iv)
        plaintext = _pkcs7_unpad(padded)
        return json.loads(plaintext.decode("utf-8"))
    except (ValueError, json.JSONDecodeError, UnicodeDecodeError) as e:
        print(f"Warning: decryption integrity check failed: {e}", file=sys.stderr)
        return None
