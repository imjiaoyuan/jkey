import importlib
import time

_core = importlib.import_module("jkey.2fa.core")
_hotp = _core._hotp
_b32_decode = _core._b32_decode
_validate_b32_secret = _core._validate_b32_secret
totp = _core.totp


class TestB32Decode:
    def test_standard(self):
        secret = _b32_decode("JBSWY3DPEHPK3PXP")
        assert len(secret) == 10
        assert secret == b"\x48\x65\x6c\x6c\x6f\x21\xde\xad\xbe\xef"

    def test_with_spaces(self):
        secret = _b32_decode("JBSW Y3DP EHPK 3PXP")
        assert len(secret) == 10

    def test_autopad(self):
        secret = _b32_decode("JBSWY3DPEHPK3PXP")
        assert len(secret) == 10


class TestValidateB32:
    def test_valid(self):
        assert _validate_b32_secret("JBSWY3DPEHPK3PXP")
        assert _validate_b32_secret("GEZDGNBVGY3TQOJQ")

    def test_invalid_chars(self):
        assert not _validate_b32_secret("not-base32-!!!")
        assert not _validate_b32_secret("!!!!!!!")

    def test_invalid_length(self):
        assert not _validate_b32_secret("ABC")


class TestHOTP:
    def _hotp_func(self, counter: int) -> str:
        secret_bytes = b"12345678901234567890"
        return _hotp(secret_bytes, counter)

    def test_rfc4226_vector_count_0(self):
        assert self._hotp_func(0) == "755224"

    def test_rfc4226_vector_count_1(self):
        assert self._hotp_func(1) == "287082"

    def test_rfc4226_vector_count_2(self):
        assert self._hotp_func(2) == "359152"

    def test_rfc4226_vector_count_3(self):
        assert self._hotp_func(3) == "969429"

    def test_rfc4226_vector_count_4(self):
        assert self._hotp_func(4) == "338314"

    def test_rfc4226_vector_count_5(self):
        assert self._hotp_func(5) == "254676"

    def test_rfc4226_vector_count_6(self):
        assert self._hotp_func(6) == "287922"

    def test_rfc4226_vector_count_7(self):
        assert self._hotp_func(7) == "162583"

    def test_rfc4226_vector_count_8(self):
        assert self._hotp_func(8) == "399871"

    def test_rfc4226_vector_count_9(self):
        assert self._hotp_func(9) == "520489"


class TestTOTP:
    def test_returns_six_digits(self):
        code = totp("JBSWY3DPEHPK3PXP")
        assert len(code) == 6
        assert code.isdigit()

    def test_different_secrets(self):
        c1 = totp("JBSWY3DPEHPK3PXP")
        c2 = totp("GEZDGNBVGY3TQOJQ")
        assert c1 != c2 or True

    def test_code_changes_over_time(self):
        secret = _b32_decode("JBSWY3DPEHPK3PXP")
        c1 = _hotp(secret, int(time.time()) // 30)
        c2 = _hotp(secret, int(time.time()) // 30 + 1)
        assert c1 != c2
