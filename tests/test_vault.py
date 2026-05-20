import json
import os

from jkey import aes


class TestEnsureDir:
    def test_creates_directories(self, vault_dir):
        from jkey.pv.core import CONFIG_DIR, QR_DIR, _ensure_dir

        _ensure_dir()
        assert os.path.isdir(CONFIG_DIR)
        assert os.path.isdir(QR_DIR)

    def test_idempotent(self, vault_dir):
        from jkey.pv.core import _ensure_dir

        _ensure_dir()
        _ensure_dir()


class TestReadWriteJkey:
    def test_write_and_read(self, vault_dir):
        from jkey.pv.core import _read_jkey, _write_jkey


        data = {"hello": "world"}
        encrypted = aes.encrypt(data, "pw")
        path = os.path.join(vault_dir, "test.jkey")
        _write_jkey(path, encrypted)
        assert os.path.exists(path)
        loaded = _read_jkey(path)
        assert loaded == encrypted
        assert aes.decrypt(loaded, "pw") == data

    def test_read_nonexistent(self, vault_dir):
        from jkey.pv.core import _read_jkey

        assert _read_jkey("/nonexistent/path.jkey") is None

    def test_read_empty_file(self, vault_dir):
        from jkey.pv.core import _read_jkey

        path = os.path.join(vault_dir, "empty.jkey")
        with open(path, "w") as f:
            f.write("")
        assert _read_jkey(path) is None


class TestEncryptDecryptFile:
    def test_roundtrip(self, vault_dir):
        from jkey.pv.core import _decrypt_file, _encrypt_file

        data = {"key": "value", "nested": {"a": [1, 2]}}
        _encrypt_file(os.path.join(vault_dir, "test.jkey"), data, "password")
        result = _decrypt_file(os.path.join(vault_dir, "test.jkey"), "password")
        assert result == data

    def test_wrong_password(self, vault_dir):
        from jkey.pv.core import _decrypt_file, _encrypt_file

        _encrypt_file(os.path.join(vault_dir, "test.jkey"), {"a": 1}, "correct")
        assert _decrypt_file(os.path.join(vault_dir, "test.jkey"), "wrong") is None

    def test_file_not_found(self, vault_dir):
        from jkey.pv.core import _decrypt_file

        assert _decrypt_file("/nonexistent.jkey", "pw") is None


class TestSession:
    def test_save_and_load(self, vault_dir):
        from jkey.pv.core import TOTP_FILE, PASSWORDS_FILE, RECOVERY_FILE, _encrypt_file, _load_session, _save_session

        _encrypt_file(TOTP_FILE, {"a": 1}, "pw")
        _encrypt_file(PASSWORDS_FILE, {"b": 2}, "pw")
        _encrypt_file(RECOVERY_FILE, {"c": 3}, "pw")

        _save_session("pw", {"a": 1}, {"b": 2}, {"c": 3})
        assert _load_session() is True
        from jkey.pv.core import _passwords_cache, _recovery_cache, _session_password, _totp_cache

        assert _session_password == "pw"
        assert _totp_cache == {"a": 1}
        assert _passwords_cache == {"b": 2}
        assert _recovery_cache == {"c": 3}

    def test_no_session_file(self, vault_dir):
        from jkey.pv.core import _load_session

        assert _load_session() is False

    def test_expired_session(self, vault_dir):
        import jkey.pv.core as core

        core._save_session("pw", {}, {}, {})
        now = core.time.time()
        from unittest.mock import patch

        with patch("jkey.pv.core.time.time", return_value=now + core.SESSION_TIMEOUT + 1):
            assert core._load_session() is False
        assert not os.path.exists(core.SESSION_FILE)

    def test_session_file_not_plaintext(self, vault_dir):
        from jkey.pv.core import SESSION_FILE, _save_session

        _save_session("pw", {"a": 1}, {"b": 2}, {"c": 3})
        with open(SESSION_FILE) as f:
            raw = json.load(f)
        assert "session" in raw
        dumped = json.dumps(raw)
        assert "\"password\"" not in dumped
        assert "\"totp\"" not in dumped

    def test_corrupted_session(self, vault_dir):
        from jkey.pv.core import SESSION_FILE, _load_session

        with open(SESSION_FILE, "w") as f:
            f.write("not json")
        assert _load_session() is False


class TestUnlockAll:
    def test_success(self, vault_dir):
        from jkey.pv.core import PASSWORDS_FILE, RECOVERY_FILE, TOTP_FILE, _encrypt_file, _unlock_all

        _encrypt_file(TOTP_FILE, {"acc": "SECRET"}, "pw")
        _encrypt_file(PASSWORDS_FILE, {"site": "pass"}, "pw")
        _encrypt_file(RECOVERY_FILE, {"acc": ["rc1"]}, "pw")
        assert _unlock_all("pw") is True
        from jkey.pv.core import _passwords_cache, _recovery_cache, _session_password, _totp_cache

        assert _session_password == "pw"
        assert _totp_cache == {"acc": "SECRET"}
        assert _passwords_cache == {"site": "pass"}
        assert _recovery_cache == {"acc": ["rc1"]}

    def test_wrong_password(self, vault_dir):
        from jkey.pv.core import TOTP_FILE, _encrypt_file, _unlock_all

        _encrypt_file(TOTP_FILE, {"acc": "SECRET"}, "correct")
        assert _unlock_all("wrong") is False
        from jkey.pv.core import _session_password

        assert _session_password is None

    def test_missing_files(self, vault_dir):
        from jkey.pv.core import _unlock_all

        assert _unlock_all("pw") is False


class TestVerifyPassword:
    def test_correct(self, vault_dir):
        from jkey.pv.core import TOTP_FILE, _encrypt_file, verify_password

        _encrypt_file(TOTP_FILE, {"a": "b"}, "pw")
        assert verify_password("pw") is True

    def test_wrong(self, vault_dir):
        from jkey.pv.core import TOTP_FILE, _encrypt_file, verify_password

        _encrypt_file(TOTP_FILE, {"a": "b"}, "pw")
        assert verify_password("wrong") is False

    def test_no_vault(self, vault_dir):
        from jkey.pv.core import verify_password

        assert verify_password("pw") is False


class TestLockUnlockState:
    def test_is_unlocked_initially_false(self, vault_dir):
        from jkey.pv.core import is_unlocked

        assert is_unlocked() is False

    def test_lock_clears_state(self, vault_dir):
        from jkey.pv.core import is_unlocked, lock

        lock()
        assert is_unlocked() is False

    def test_lock_when_locked(self, vault_dir):
        from jkey.pv.core import is_unlocked, lock

        lock()
        assert is_unlocked() is False


class TestLoadSaveTotp:
    def test_save_and_load(self, vault):
        from jkey.pv.core import load_totp, save_totp

        save_totp({"user@example.com": "JBSWY3DPEHPK3PXP"})
        assert load_totp() == {"user@example.com": "JBSWY3DPEHPK3PXP"}

    def test_update(self, vault):
        from jkey.pv.core import load_totp, save_totp

        save_totp({"a": "SECRET1"})
        save_totp({"a": "SECRET1", "b": "SECRET2"})
        assert load_totp() == {"a": "SECRET1", "b": "SECRET2"}

    def test_load_when_locked(self, vault_dir):
        from jkey.pv.core import load_totp

        assert load_totp() is None


class TestLoadSavePasswords:
    def test_save_and_load(self, vault):
        from jkey.pv.core import load_passwords, save_passwords

        save_passwords({"github": "mypassword"})
        assert load_passwords() == {"github": "mypassword"}

    def test_load_when_locked(self, vault_dir):
        from jkey.pv.core import load_passwords

        assert load_passwords() is None


class TestLoadSaveRecovery:
    def test_save_and_load(self, vault):
        from jkey.pv.core import load_recovery, save_recovery

        save_recovery({"example": ["code1", "code2"]})
        assert load_recovery() == {"example": ["code1", "code2"]}

    def test_load_when_locked(self, vault_dir):
        from jkey.pv.core import load_recovery

        assert load_recovery() is None


class TestQRImages:
    def test_save_and_load(self, vault):
        from jkey.pv.core import load_qr_image, save_qr_image

        save_qr_image("test", b"fake_image_data")
        loaded = load_qr_image("test")
        assert loaded == b"fake_image_data"

    def test_load_nonexistent(self, vault):
        from jkey.pv.core import load_qr_image

        assert load_qr_image("nonexistent") is None

    def test_list_qr(self, vault):
        from jkey.pv.core import list_qr_images, save_qr_image

        save_qr_image("a", b"data_a")
        save_qr_image("b", b"data_b")
        assert list_qr_images() == ["a", "b"]

    def test_list_empty(self, vault_dir):
        from jkey.pv.core import list_qr_images

        assert list_qr_images() == []

    def test_save_when_locked(self, vault_dir):
        from jkey.pv.core import save_qr_image

        save_qr_image("test", b"data")


class TestEnsureUnlocked:
    def test_already_unlocked(self, vault):
        from jkey.pv.core import _ensure_unlocked

        assert _ensure_unlocked() is True

    def test_no_vault(self, vault_dir):
        from jkey.pv.core import _ensure_unlocked

        assert _ensure_unlocked() is False

    def test_with_env_password(self, vault_dir, monkeypatch):
        from jkey.pv.core import TOTP_FILE, _encrypt_file, _ensure_unlocked

        _encrypt_file(TOTP_FILE, {"a": "b"}, "env-pw")
        monkeypatch.setenv("JKEY_PASS", "env-pw")
        assert _ensure_unlocked() is True

    def test_with_wrong_env_password(self, vault_dir, monkeypatch):
        from jkey.pv.core import TOTP_FILE, _encrypt_file, _ensure_unlocked

        _encrypt_file(TOTP_FILE, {"a": "b"}, "correct-pw")
        monkeypatch.setenv("JKEY_PASS", "wrong-pw")
        monkeypatch.setattr("getpass.getpass", lambda p="": "wrong-too")
        assert _ensure_unlocked() is False

    def test_with_session(self, vault_dir):
        from jkey.pv.core import (
            TOTP_FILE,
            _encrypt_file,
            _ensure_unlocked,
            _save_session,
        )

        _encrypt_file(TOTP_FILE, {"a": "b"}, "pw")
        _save_session("pw", {"a": "b"}, {}, {})
        assert _ensure_unlocked() is True


class TestPromptPassword:
    def test_interactive_correct(self, vault_dir, monkeypatch):
        """Test ensure_unlocked with interactive password prompt."""
        from jkey.pv.core import TOTP_FILE, _encrypt_file, _ensure_unlocked

        _encrypt_file(TOTP_FILE, {"a": "b"}, "correct")
        monkeypatch.setattr("getpass.getpass", lambda p="": "correct")
        assert _ensure_unlocked() is True

    def test_interactive_wrong_then_correct(self, vault_dir, monkeypatch):
        """Test 3 attempts with wrong then correct password."""
        from jkey.pv.core import TOTP_FILE, _encrypt_file, _ensure_unlocked

        _encrypt_file(TOTP_FILE, {"a": "b"}, "correct")
        answers = iter(["wrong1", "wrong2", "correct"])

        monkeypatch.setattr("getpass.getpass", lambda p="": next(answers))
        assert _ensure_unlocked() is True

    def test_interactive_all_wrong(self, vault_dir, monkeypatch):
        """Test 3 wrong attempts should fail."""
        from jkey.pv.core import TOTP_FILE, _encrypt_file, _ensure_unlocked

        _encrypt_file(TOTP_FILE, {"a": "b"}, "correct")
        monkeypatch.setattr("getpass.getpass", lambda p="": "wrong")
        assert _ensure_unlocked() is False
