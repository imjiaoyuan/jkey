import json
import os

import pytest

from jkey import aes
from jkey.errors import JkeyError


class TestEnsureDir:
    def test_creates_directories(self, vault_dir):
        from jkey.pv.core import CONFIG_DIR, QR_DIR, ensure_dir

        ensure_dir()
        assert os.path.isdir(CONFIG_DIR)
        assert os.path.isdir(QR_DIR)

    def test_idempotent(self, vault_dir):
        from jkey.pv.core import ensure_dir

        ensure_dir()
        ensure_dir()


class TestReadWriteJkey:
    def test_write_and_read(self, vault_dir):
        from jkey.pv.core import read_jkey, write_jkey

        data = {"hello": "world"}
        encrypted = aes.encrypt(data, "pw")
        path = os.path.join(vault_dir, "test.jkey")
        write_jkey(path, encrypted)
        assert os.path.exists(path)
        loaded = read_jkey(path)
        assert loaded == encrypted
        assert aes.decrypt(loaded, "pw") == data

    def test_read_nonexistent(self, vault_dir):
        from jkey.pv.core import read_jkey

        assert read_jkey("/nonexistent/path.jkey") is None

    def test_read_empty_file(self, vault_dir, capsys):
        from jkey.pv.core import read_jkey

        path = os.path.join(vault_dir, "empty.jkey")
        with open(path, "w") as f:
            f.write("")
        with pytest.raises(JkeyError, match="cannot read vault file"):
            read_jkey(path)


class TestEncryptDecryptFile:
    def test_roundtrip(self, vault_dir):
        from jkey.pv.core import encrypt_file, read_jkey

        data = {"key": "value", "nested": {"a": [1, 2]}}
        path = os.path.join(vault_dir, "test.jkey")
        encrypt_file(path, data, "password")
        assert aes.decrypt(read_jkey(path), "password") == data

    def test_wrong_password(self, vault_dir):
        from jkey.pv.core import encrypt_file, read_jkey

        path = os.path.join(vault_dir, "test.jkey")
        encrypt_file(path, {"a": 1}, "correct")
        assert aes.decrypt(read_jkey(path), "wrong") is None

    def test_file_not_found(self, vault_dir):
        from jkey.pv.core import read_jkey

        assert read_jkey("/nonexistent.jkey") is None


class TestSession:
    def test_save_and_load(self, vault_dir):
        from jkey.pv.core import PASSWORDS_FILE, RECOVERY_FILE, TOTP_FILE, _load_session, _save_session, encrypt_file

        encrypt_file(TOTP_FILE, {"a": 1}, "pw")
        encrypt_file(PASSWORDS_FILE, {"b": 2}, "pw")
        encrypt_file(RECOVERY_FILE, {"c": 3}, "pw")

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
        assert not os.path.exists(core._session_file())

    def test_session_file_format(self, vault_dir):
        import jkey.pv.core as core
        from jkey.pv.core import _save_session

        _save_session("pw", {"a": 1}, {"b": 2}, {"c": 3})
        with open(core._session_file()) as f:
            raw = json.load(f)
        assert raw["sv"] == 3
        assert raw["password"] == "pw"
        assert raw["totp"] == {"a": 1}
        assert raw["passwords"] == {"b": 2}
        assert raw["recovery"] == {"c": 3}
        assert "expires" in raw

    def test_corrupted_session(self, vault_dir):
        import jkey.pv.core as core
        from jkey.pv.core import _load_session

        os.makedirs(core.SESSION_DIR, exist_ok=True)
        with open(core._session_file(), "w") as f:
            f.write("not json")
        assert _load_session() is False

    def test_session_missing_fields(self, vault_dir):
        import jkey.pv.core as core
        from jkey.pv.core import _load_session

        os.makedirs(core.SESSION_DIR, exist_ok=True)
        with open(core._session_file(), "w") as f:
            json.dump({"sv": 3, "password": "pw"}, f)
        assert _load_session() is False
        assert not os.path.exists(core._session_file())

    def test_has_session_false_without_file(self, vault_dir):
        from jkey.pv.core import has_session

        assert has_session() is False

    def test_has_session_true_after_unlock(self, vault):
        from jkey.pv.core import has_session

        assert has_session() is True


class TestTtyTickets:
    """sudo-style per-terminal sessions: each TTY gets its own ticket."""

    def test_other_terminal_ticket_not_loaded(self, vault, monkeypatch):
        import jkey.pv.core as core

        # Terminal A unlocks (vault fixture already did) -> ticket saved for A.
        assert core.has_session() is True
        # Terminal B (different TTY) must not see A's ticket.
        monkeypatch.setattr(core, "_terminal_id", lambda: "/dev/pts/1")
        assert core._load_session() is False
        assert core.has_session(this_terminal_only=True) is False
        # ...but the global view (status/lock) still sees A's live ticket.
        assert core.has_session() is True

    def test_same_terminal_ticket_reloads(self, vault, monkeypatch):
        import jkey.pv.core as core

        tid = "/dev/pts/42"
        monkeypatch.setattr(core, "_terminal_id", lambda: tid)
        core._save_session("pw", {"a": 1}, {}, {})
        core._session_password = None
        core._totp_cache = None
        assert core._load_session() is True
        assert core._session_password == "pw"

    def test_lock_clears_all_terminals(self, vault, monkeypatch):
        import jkey.pv.core as core

        for tid in ("/dev/pts/1", "/dev/pts/2", "/dev/pts/3"):
            monkeypatch.setattr(core, "_terminal_id", lambda t=tid: t)
            core._save_session("pw", {}, {}, {})
        assert core.has_session() is True
        core.lock()
        assert core.has_session() is False
        assert list(core._iter_session_files()) == []

    def test_no_tty_shares_none_slot(self, vault, monkeypatch):
        import jkey.pv.core as core

        monkeypatch.setattr(core, "_terminal_id", lambda: "none")
        core._save_session("pw", {}, {}, {})
        monkeypatch.setattr(core, "_terminal_id", lambda: "/dev/pts/9")
        assert core._load_session() is False  # TTY process does not see the no-TTY ticket

    def test_ticket_invalidated_when_vault_files_change(self, vault, monkeypatch):
        import jkey.pv.core as core

        # Terminal A holds a ticket...
        monkeypatch.setattr(core, "_terminal_id", lambda: "/dev/pts/1")
        core._save_session("pw", {"a": 1}, {}, {})
        # ...then terminal B writes -> on-disk fingerprint changes.
        monkeypatch.setattr(core, "_terminal_id", lambda: "/dev/pts/2")
        core.save_totp({"other": "B"})
        # A's cached data is now stale: its ticket must be rejected, not reloaded.
        monkeypatch.setattr(core, "_terminal_id", lambda: "/dev/pts/1")
        core._session_password = None
        core._totp_cache = None
        assert core._load_session() is False
        assert not os.path.exists(core._session_file())

    def test_legacy_dot_session_removed(self, vault):
        import jkey.pv.core as core

        with open(core._LEGACY_SESSION_FILE, "w") as f:
            f.write('{"sv": 3, "password": "old"}')
        core._save_session("pw", {}, {}, {})
        assert not os.path.exists(core._LEGACY_SESSION_FILE)


class TestUnlockAll:
    def test_success(self, vault_dir):
        from jkey.pv.core import PASSWORDS_FILE, RECOVERY_FILE, TOTP_FILE, encrypt_file, unlock_all

        encrypt_file(TOTP_FILE, {"acc": "SECRET"}, "pw")
        encrypt_file(PASSWORDS_FILE, {"site": "pass"}, "pw")
        encrypt_file(RECOVERY_FILE, {"acc": ["rc1"]}, "pw")
        assert unlock_all("pw") is True
        from jkey.pv.core import _passwords_cache, _recovery_cache, _session_password, _totp_cache

        assert _session_password == "pw"
        assert _totp_cache == {"acc": "SECRET"}
        assert _passwords_cache == {"site": "pass"}
        assert _recovery_cache == {"acc": ["rc1"]}

    def test_wrong_password(self, vault_dir):
        from jkey.pv.core import TOTP_FILE, encrypt_file, unlock_all

        encrypt_file(TOTP_FILE, {"acc": "SECRET"}, "correct")
        assert unlock_all("wrong") is False
        from jkey.pv.core import _session_password

        assert _session_password is None

    def test_missing_files(self, vault_dir):
        from jkey.pv.core import unlock_all

        assert unlock_all("pw") is False


class TestVerifyPassword:
    def test_correct(self, vault_dir):
        from jkey.pv.core import TOTP_FILE, encrypt_file, verify_password

        encrypt_file(TOTP_FILE, {"a": "b"}, "pw")
        assert verify_password("pw") is True

    def test_wrong(self, vault_dir):
        from jkey.pv.core import TOTP_FILE, encrypt_file, verify_password

        encrypt_file(TOTP_FILE, {"a": "b"}, "pw")
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

        with pytest.raises(JkeyError, match="Vault not initialized"):
            load_totp()

    def test_load_returns_copy(self, vault):
        from jkey.pv.core import load_totp, save_totp

        save_totp({"a": "b"})
        data = load_totp()
        data["c"] = "d"
        assert load_totp() == {"a": "b"}


class TestLoadSavePasswords:
    def test_save_and_load(self, vault):
        from jkey.pv.core import load_passwords, save_passwords

        save_passwords({"github": "mypassword"})
        assert load_passwords() == {"github": "mypassword"}

    def test_load_when_locked(self, vault_dir):
        from jkey.pv.core import load_passwords

        with pytest.raises(JkeyError, match="Vault not initialized"):
            load_passwords()


class TestLoadSaveRecovery:
    def test_save_and_load(self, vault):
        from jkey.pv.core import load_recovery, save_recovery

        save_recovery({"example": ["code1", "code2"]})
        assert load_recovery() == {"example": ["code1", "code2"]}

    def test_load_when_locked(self, vault_dir):
        from jkey.pv.core import load_recovery

        with pytest.raises(JkeyError, match="Vault not initialized"):
            load_recovery()


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

    def test_save_when_locked(self, vault_dir, capsys):
        from jkey.pv.core import save_qr_image

        with pytest.raises(JkeyError, match="vault is locked"):
            save_qr_image("test", b"data")


class TestEnsureUnlocked:
    def test_already_unlocked(self, vault):
        from jkey.pv.core import ensure_unlocked

        assert ensure_unlocked() is None

    def test_no_vault(self, vault_dir):
        from jkey.pv.core import ensure_unlocked

        with pytest.raises(JkeyError, match="Vault not initialized"):
            ensure_unlocked()

    def test_with_env_password(self, vault_dir, monkeypatch):
        from jkey.pv.core import TOTP_FILE, encrypt_file, ensure_unlocked

        encrypt_file(TOTP_FILE, {"a": "b"}, "env-pw")
        monkeypatch.setenv("JKEY_PASS", "env-pw")
        assert ensure_unlocked() is None

    def test_with_wrong_env_password(self, vault_dir, monkeypatch):
        from jkey.pv.core import TOTP_FILE, encrypt_file, ensure_unlocked

        encrypt_file(TOTP_FILE, {"a": "b"}, "correct-pw")
        monkeypatch.setenv("JKEY_PASS", "wrong-pw")
        monkeypatch.setattr("getpass.getpass", lambda p="": "wrong-too")
        with pytest.raises(JkeyError, match="JKEY_PASS environment variable contains incorrect password"):
            ensure_unlocked()

    def test_with_session(self, vault_dir):
        from jkey.pv.core import (
            TOTP_FILE,
            _save_session,
            encrypt_file,
            ensure_unlocked,
        )

        encrypt_file(TOTP_FILE, {"a": "b"}, "pw")
        _save_session("pw", {"a": "b"}, {}, {})
        assert ensure_unlocked() is None


class TestPromptPassword:
    def test_interactive_correct(self, vault_dir, monkeypatch):
        """Test ensure_unlocked with interactive password prompt."""
        from jkey.pv.core import TOTP_FILE, encrypt_file, ensure_unlocked

        encrypt_file(TOTP_FILE, {"a": "b"}, "correct")
        monkeypatch.setattr("getpass.getpass", lambda p="": "correct")
        assert ensure_unlocked() is None

    def test_interactive_wrong_then_correct(self, vault_dir, monkeypatch):
        """Test 3 attempts with wrong then correct password."""
        from jkey.pv.core import TOTP_FILE, encrypt_file, ensure_unlocked

        encrypt_file(TOTP_FILE, {"a": "b"}, "correct")
        answers = iter(["wrong1", "wrong2", "correct"])

        monkeypatch.setattr("getpass.getpass", lambda p="": next(answers))
        monkeypatch.setattr("time.sleep", lambda s: None)
        assert ensure_unlocked() is None

    def test_interactive_all_wrong(self, vault_dir, monkeypatch):
        """Test 3 wrong attempts should fail."""
        from jkey.pv.core import TOTP_FILE, encrypt_file, ensure_unlocked

        encrypt_file(TOTP_FILE, {"a": "b"}, "correct")
        monkeypatch.setattr("getpass.getpass", lambda p="": "wrong")
        monkeypatch.setattr("time.sleep", lambda s: None)
        with pytest.raises(JkeyError, match="Failed to unlock vault"):
            ensure_unlocked()


class TestSessionV2:
    def test_save_and_load_sv3(self, vault_dir):
        import jkey.pv.core as core

        core.encrypt_file(core.TOTP_FILE, {"a": 1}, "pw")
        core.encrypt_file(core.PASSWORDS_FILE, {"a": 1}, "pw")
        core.encrypt_file(core.RECOVERY_FILE, {"a": 1}, "pw")

        core._save_session("pw", {"a": 1}, {}, {})
        with open(core._session_file()) as f:
            raw = json.load(f)
        assert raw["sv"] == 3
        assert core._load_session() is True

    def test_activity_based_timeout_reset(self, vault_dir, monkeypatch):
        import jkey.pv.core as core

        core.encrypt_file(core.TOTP_FILE, {"a": 1}, "pw")
        core.encrypt_file(core.PASSWORDS_FILE, {}, "pw")
        core.encrypt_file(core.RECOVERY_FILE, {}, "pw")

        core._save_session("pw", {"a": 1}, {}, {})
        original_expires = json.load(open(core._session_file()))["expires"]

        import time as _time

        _time.sleep(0.01)

        assert core._load_session() is True
        new_expires = json.load(open(core._session_file()))["expires"]
        assert new_expires > original_expires

    def test_old_session_rejected(self, vault_dir):
        import jkey.pv.core as core

        core.encrypt_file(core.TOTP_FILE, {"old": "data"}, "pw")
        old_session = {
            "sv": 2,
            "password": "pw",
            "totp": {"old": "data"},
            "passwords": {},
            "recovery": {},
            "expires": core.time.time() + 300,
        }
        os.makedirs(core.SESSION_DIR, exist_ok=True)
        with open(core._session_file(), "w") as f:
            json.dump(old_session, f)
        assert core._load_session() is False


class TestSaveWhenLocked:
    def test_save_totp_locked(self, vault_dir, capsys):
        from jkey.pv.core import save_totp

        with pytest.raises(JkeyError, match="vault is locked"):
            save_totp({"test": "secret"})

    def test_save_passwords_locked(self, vault_dir, capsys):
        from jkey.pv.core import save_passwords

        with pytest.raises(JkeyError, match="vault is locked"):
            save_passwords({"test": "secret"})

    def test_save_recovery_locked(self, vault_dir, capsys):
        from jkey.pv.core import save_recovery

        with pytest.raises(JkeyError, match="vault is locked"):
            save_recovery({"test": ["rc1"]})

    def test_save_qr_locked(self, vault_dir, capsys):
        from jkey.pv.core import save_qr_image

        with pytest.raises(JkeyError, match="vault is locked"):
            save_qr_image("test", b"data")


class TestStaleTmpHandling:
    def test_write_jkey_removes_stale_tmp(self, vault_dir):
        from jkey.pv.core import write_jkey

        path = os.path.join(vault_dir, "test.jkey")
        tmp = path + ".tmp"
        with open(tmp, "w") as f:
            f.write("stale")
        os.chmod(tmp, 0o600)
        write_jkey(path, {"test": "data"})
        assert os.path.exists(path)
        assert not os.path.exists(tmp)


class TestJkeyExtConstant:
    def test_qr_path_uses_constant(self):
        from jkey.pv.core import _JKEY_EXT, QR_DIR, _qr_path, _sanitize_filename

        p = _qr_path("test")
        assert p == os.path.join(QR_DIR, f"{_sanitize_filename('test')}{_JKEY_EXT}")

    def test_list_qr_images_uses_constant(self, vault):
        from jkey.pv.core import list_qr_images, save_qr_image

        save_qr_image("uses_const", b"data")
        names = list_qr_images()
        assert "uses_const" in names


class TestChangeMasterPassword:
    def test_staging_failure_keeps_old_files(self, vault):
        """A write failure mid-re-encrypt must leave all vault files on the old password."""
        import jkey.pv.core as core

        core.save_totp({"acc": "SECRET"})
        core.save_passwords({"site": "pass"})

        def fail_replace(src, dst):
            raise OSError("disk full")

        # Separate MonkeyPatch scope: undo() here must not revert the vault_dir fixture's patches.
        mp = pytest.MonkeyPatch()
        mp.setattr("jkey.pv.core.os.replace", fail_replace)
        try:
            with pytest.raises(JkeyError, match="failed to re-encrypt vault"):
                core.change_master_password("New-Password-123!")
        finally:
            mp.undo()

        assert core.verify_password("test-password") is True
        assert core.verify_password("New-Password-123!") is False

    def test_success_rekeys_all_files(self, vault):
        import jkey.pv.core as core

        core.save_totp({"acc": "SECRET"})
        assert core.change_master_password("New-Password-123!") is True
        assert core._session_password == "New-Password-123!"
        assert core.verify_password("New-Password-123!") is True
        assert core.verify_password("test-password") is False
        assert core.load_totp() == {"acc": "SECRET"}
