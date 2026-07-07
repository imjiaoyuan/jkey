import pytest

from jkey.pm.get import _SYMBOLS as SYMBOLS
from jkey.pm.get import generate_password


class TestGeneratePassword:
    def test_default_length(self):
        pw = generate_password()
        assert len(pw) == 16

    def test_custom_length(self):
        pw = generate_password(length=32)
        assert len(pw) == 32

    def test_length_1(self):
        pw = generate_password(length=1, uppercase=False, digits=False, symbols=False)
        assert len(pw) == 1

    def test_all_char_sets_included(self):
        pw = generate_password(length=64)
        has_lower = any(c.islower() for c in pw)
        has_upper = any(c.isupper() for c in pw)
        has_digit = any(c.isdigit() for c in pw)
        has_symbol = any(c in SYMBOLS for c in pw)
        assert has_lower, "Missing lowercase"
        assert has_upper, "Missing uppercase"
        assert has_digit, "Missing digit"
        assert has_symbol, "Missing symbol"

    def test_only_lowercase(self):
        pw = generate_password(length=32, uppercase=False, digits=False, symbols=False)
        assert pw.islower()
        assert len(pw) == 32

    def test_only_uppercase(self):
        pw = generate_password(length=32, lowercase=False, digits=False, symbols=False)
        assert pw.isupper()
        assert len(pw) == 32

    def test_only_digits(self):
        pw = generate_password(length=32, uppercase=False, lowercase=False, symbols=False)
        assert pw.isdigit()
        assert len(pw) == 32

    def test_no_symbols(self):
        pw = generate_password(length=32, symbols=False)
        assert all(c not in SYMBOLS for c in pw)

    def test_no_char_sets_raises(self):
        with pytest.raises(ValueError, match="At least one character set"):
            generate_password(length=8, uppercase=False, lowercase=False, digits=False, symbols=False)

    def test_length_too_small_raises(self):
        with pytest.raises(ValueError, match="Length too small"):
            generate_password(length=1, uppercase=True, lowercase=True, digits=True, symbols=True)

    def test_uniqueness(self):
        passwords = {generate_password() for _ in range(20)}
        assert len(passwords) >= 18

    def test_no_predictable_pattern(self):
        pw = generate_password(length=100)
        for c in set(pw):
            assert pw.count(c * 5) == 0
