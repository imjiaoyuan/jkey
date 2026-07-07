import base64
import hashlib
import hmac
import json
import os

from jkey import aes


class TestEncryptDecrypt:
    def test_roundtrip(self):
        data = {"hello": "world", "nested": {"a": [1, 2, 3]}}
        encrypted = aes.encrypt(data, "correct-password")
        assert encrypted["version"] == 3
        decrypted = aes.decrypt(encrypted, "correct-password")
        assert decrypted == data

    def test_wrong_password(self):
        data = {"key": "value"}
        encrypted = aes.encrypt(data, "password")
        assert aes.decrypt(encrypted, "wrong-password") is None

    def test_empty_dict(self):
        encrypted = aes.encrypt({}, "password")
        assert aes.decrypt(encrypted, "password") == {}

    def test_unicode_data(self):
        data = {"中文": "测试", "emoji": "🔐"}
        encrypted = aes.encrypt(data, "password")
        assert aes.decrypt(encrypted, "password") == data

    def test_long_password(self):
        data = {"key": "value"}
        pw = "x" * 1000
        encrypted = aes.encrypt(data, pw)
        assert aes.decrypt(encrypted, pw) == data

    def test_malformed_data(self):
        assert aes.decrypt({}, "password") is None
        assert aes.decrypt({"version": 2}, "password") is None
        assert aes.decrypt({"salt": "!!!", "iv": "", "data": "", "mac": ""}, "password") is None

    def test_corrupted_ciphertext(self):
        data = {"key": "value"}
        encrypted = aes.encrypt(data, "password")
        ct = bytearray(base64.b64decode(encrypted["data"]))
        ct[0] ^= 0xFF
        encrypted["data"] = base64.b64encode(bytes(ct)).decode()
        assert aes.decrypt(encrypted, "password") is None

    def test_corrupted_mac(self):
        data = {"key": "value"}
        encrypted = aes.encrypt(data, "password")
        mac = bytearray(base64.b64decode(encrypted["mac"]))
        mac[0] ^= 0xFF
        encrypted["mac"] = base64.b64encode(bytes(mac)).decode()
        assert aes.decrypt(encrypted, "password") is None

    def test_iv_used(self):
        data = {"key": "value"}
        e1 = aes.encrypt(data, "password")
        e2 = aes.encrypt(data, "password")
        assert e1["salt"] != e2["salt"]
        assert e1["iv"] != e2["iv"]
        assert e1["data"] != e2["data"]


class TestV2Compat:
    def _make_v2(self, data: dict, password: str) -> dict:
        salt = os.urandom(16)
        iv = os.urandom(16)
        key = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 600_000, dklen=32)
        plaintext = json.dumps(data, ensure_ascii=False).encode()
        padded = aes._pkcs7_pad(plaintext)
        ct = aes.aes_cbc_encrypt(padded, key, iv)
        mac = hmac.new(key, iv + ct, hashlib.sha256).digest()
        return {
            "version": 2,
            "salt": base64.b64encode(salt).decode(),
            "iv": base64.b64encode(iv).decode(),
            "data": base64.b64encode(ct).decode(),
            "mac": base64.b64encode(mac).decode(),
        }

    def test_v2_decrypt(self):
        data = {"hello": "world"}
        v2 = self._make_v2(data, "password")
        assert v2["version"] == 2
        decrypted = aes.decrypt(v2, "password")
        assert decrypted == data

    def test_v2_wrong_password(self):
        v2 = self._make_v2({"a": 1}, "password")
        assert aes.decrypt(v2, "wrong") is None

    def test_v2_roundtrip_then_v3(self):
        data = {"key": "value"}
        v2 = self._make_v2(data, "pass")
        assert aes.decrypt(v2, "pass") == data
        v3 = aes.encrypt(data, "pass")
        assert v3["version"] == 3
        assert aes.decrypt(v3, "pass") == data
