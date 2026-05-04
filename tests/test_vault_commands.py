import os

import pytest


class TestCmdInit:
    def test_init_creates_vault(self, vault_dir, monkeypatch):
        monkeypatch.setattr("getpass.getpass", lambda p="": "test-pw")
        from jkey.pv.init import cmd_init

        from jkey.pv.core import CONFIG_DIR, TOTP_FILE, PASSWORDS_FILE, RECOVERY_FILE

        cmd_init()
        assert os.path.exists(TOTP_FILE)
        assert os.path.exists(PASSWORDS_FILE)
        assert os.path.exists(RECOVERY_FILE)
        assert os.path.isdir(CONFIG_DIR)
        from jkey.pv.core import is_unlocked

        assert is_unlocked() is True

    def test_init_already_exists(self, vault_dir, capsys, monkeypatch):
        monkeypatch.setattr("getpass.getpass", lambda p="": "test-pw")
        from jkey.pv.init import cmd_init

        cmd_init()
        capsys.readouterr()
        cmd_init()
        captured = capsys.readouterr()
        assert "already exists" in captured.out

    def test_init_with_env_password(self, vault_dir, monkeypatch, capsys):
        from jkey.pv.init import cmd_init

        monkeypatch.setenv("JKEY_PASS", "env-pass")
        cmd_init()
        captured = capsys.readouterr()
        assert "Vault initialized" in captured.out
        from jkey.pv.core import is_unlocked

        assert is_unlocked() is True

    def test_init_with_mismatch(self, vault_dir, monkeypatch, capsys):
        """Test that password confirmation mismatch aborts."""
        from jkey.pv.init import cmd_init

        answers = iter(["password1", "password2"])
        monkeypatch.setattr("getpass.getpass", lambda p="": next(answers))
        cmd_init()
        captured = capsys.readouterr()
        assert "do not match" in captured.out

    def test_init_with_empty_password(self, vault_dir, monkeypatch, capsys):
        from jkey.pv.init import cmd_init

        monkeypatch.setattr("getpass.getpass", lambda p="": "")
        cmd_init()
        captured = capsys.readouterr()
        assert "cannot be empty" in captured.out


class TestCmdUnlock:
    def test_unlock_no_vault(self, vault_dir, capsys):
        from jkey.pv.unlock import cmd_unlock

        cmd_unlock()
        captured = capsys.readouterr()
        assert "not initialized" in captured.out

    def test_unlock_already_unlocked(self, vault, capsys):
        from jkey.pv.unlock import cmd_unlock

        cmd_unlock()
        captured = capsys.readouterr()
        assert "already unlocked" in captured.out

    def test_unlock_success(self, vault_dir, capsys, monkeypatch):
        from jkey.pv.core import TOTP_FILE, _encrypt_file, is_unlocked

        _encrypt_file(TOTP_FILE, {"a": "b"}, "pw")
        monkeypatch.setattr("getpass.getpass", lambda p="": "pw")

        from jkey.pv.unlock import cmd_unlock

        cmd_unlock()
        captured = capsys.readouterr()
        assert "Vault unlocked" in captured.out
        assert is_unlocked() is True


class TestCmdLock:
    def test_lock_already_locked(self, vault_dir, capsys):
        from jkey.pv.lock import cmd_lock

        cmd_lock()
        captured = capsys.readouterr()
        assert "already locked" in captured.out

    def test_lock_success(self, vault, capsys):
        from jkey.pv.lock import cmd_lock

        from jkey.pv.core import is_unlocked

        cmd_lock()
        captured = capsys.readouterr()
        assert "Vault locked" in captured.out
        assert is_unlocked() is False


class TestCmdSetPw:
    def test_set_pw_no_vault(self, vault_dir, capsys):
        from jkey.pv.set_pw import cmd_set_pw

        cmd_set_pw()
        captured = capsys.readouterr()
        assert "not initialized" in captured.out

    def test_set_pw_success(self, vault, capsys, monkeypatch):
        from jkey.pv.set_pw import cmd_set_pw

        from jkey.pv.core import TOTP_FILE, _decrypt_file
        import jkey.pv.core as core

        answers = iter(["new-password", "new-password"])
        monkeypatch.setattr("getpass.getpass", lambda p="": next(answers))
        cmd_set_pw()
        captured = capsys.readouterr()
        assert "changed" in captured.out
        assert core._session_password == "new-password"
        # Verify old password no longer works
        assert _decrypt_file(TOTP_FILE, "test-password") is None
        assert _decrypt_file(TOTP_FILE, "new-password") is not None

    def test_set_pw_mismatch(self, vault, capsys, monkeypatch):
        from jkey.pv.set_pw import cmd_set_pw

        answers = iter(["pw1", "pw2"])
        monkeypatch.setattr("getpass.getpass", lambda p="": next(answers))
        cmd_set_pw()
        captured = capsys.readouterr()
        assert "do not match" in captured.out

    def test_set_pw_empty(self, vault, capsys, monkeypatch):
        from jkey.pv.set_pw import cmd_set_pw

        monkeypatch.setattr("getpass.getpass", lambda p="": "")
        cmd_set_pw()
        captured = capsys.readouterr()
        assert "cannot be empty" in captured.out


class TestCmdEncrypt:
    def test_encrypt_file(self, vault, tmp_path, capsys):
        from jkey.pv.encrypt import encrypt_file

        input_path = tmp_path / "secret.txt"
        input_path.write_text("hello world")
        encrypt_file(str(input_path))
        captured = capsys.readouterr()
        assert ".jkey" in captured.out
        output_path = tmp_path / "secret.txt.jkey"
        assert output_path.exists()

    def test_encrypt_with_output(self, vault, tmp_path, capsys):
        from jkey.pv.encrypt import encrypt_file

        input_path = tmp_path / "secret.txt"
        input_path.write_text("hello")
        out = tmp_path / "encrypted.jkey"
        encrypt_file(str(input_path), str(out))
        captured = capsys.readouterr()
        assert "Encrypted" in captured.out
        assert out.exists()

    def test_encrypt_file_not_found(self, vault, capsys):
        from jkey.pv.encrypt import encrypt_file

        encrypt_file("/nonexistent/file")
        captured = capsys.readouterr()
        assert "not found" in captured.out


class TestCmdDecrypt:
    def test_decrypt_with_output(self, vault, tmp_path, capsys):
        from jkey.pv.decrypt import decrypt_file
        from jkey.pv.encrypt import encrypt_file

        input_path = tmp_path / "secret.txt"
        input_path.write_text("hello world")
        encrypted_path = tmp_path / "secret.txt.jkey"
        encrypt_file(str(input_path), str(encrypted_path))
        capsys.readouterr()  # discard encrypt output

        out = tmp_path / "decrypted.txt"
        decrypt_file(str(encrypted_path), str(out))
        captured = capsys.readouterr()
        assert "Decrypted" in captured.out
        assert out.read_text() == "hello world"

    def test_decrypt_file_not_found(self, vault, capsys):
        from jkey.pv.decrypt import decrypt_file

        decrypt_file("/nonexistent.jkey")
        captured = capsys.readouterr()
        assert "not found" in captured.out

    def test_decrypt_wrong_password(self, vault, tmp_path, capsys):
        """Test decrypt with wrong session password."""
        import jkey.pv.core as core
        from jkey.pv.decrypt import decrypt_file
        from jkey import aes

        encrypted = aes.encrypt({"raw": "dGVzdA=="}, "correct")

        encrypted_path = tmp_path / "test.jkey"
        import json

        with open(encrypted_path, "w") as f:
            json.dump(encrypted, f)

        original = core._session_password
        core._session_password = "wrong"
        try:
            decrypt_file(str(encrypted_path))
        finally:
            core._session_password = original
        captured = capsys.readouterr()
        assert "Decryption failed" in captured.out


class TestCmdExport:
    def test_export_totp(self, vault, capsys, monkeypatch):
        monkeypatch.setattr("getpass.getpass", lambda p="": "test-password")
        from jkey.pv.export import cmd_export

        class Args:
            type = "totp"
            output = None

        cmd_export(Args())
        captured = capsys.readouterr()
        # Should print JSON to stdout
        assert "{" in captured.out or "Warning" in captured.out

    def test_export_passwords(self, vault, tmp_path, capsys, monkeypatch):
        monkeypatch.setattr("getpass.getpass", lambda p="": "test-password")
        from jkey.pv.export import cmd_export

        from jkey.pv.core import save_passwords

        save_passwords({"github": "gh_pass"})
        out = tmp_path / "passwords.csv"
        args = type("Args", (), {"type": "passwords", "output": str(out)})
        cmd_export(args)
        captured = capsys.readouterr()
        assert "Exported" in captured.out
        assert out.exists()
        assert "name,password" in out.read_text()

    def test_export_recovery(self, vault, tmp_path, capsys, monkeypatch):
        monkeypatch.setattr("getpass.getpass", lambda p="": "test-password")
        from jkey.pv.export import cmd_export

        from jkey.pv.core import save_recovery

        save_recovery({"example": ["rc1"]})
        out = tmp_path / "recovery.txt"
        args = type("Args", (), {"type": "recovery", "output": str(out)})
        cmd_export(args)
        captured = capsys.readouterr()
        assert "Exported" in captured.out
        assert out.exists()

    def test_export_qr_no_output(self, vault, capsys, monkeypatch):
        monkeypatch.setattr("getpass.getpass", lambda p="": "test-password")
        from jkey.pv.export import cmd_export

        args = type("Args", (), {"type": "qr", "output": None})
        cmd_export(args)
        captured = capsys.readouterr()
        assert "-o" in captured.out

    def test_export_all_no_output(self, vault, capsys, monkeypatch):
        monkeypatch.setattr("getpass.getpass", lambda p="": "test-password")
        from jkey.pv.export import cmd_export

        args = type("Args", (), {"type": "all", "output": None})
        cmd_export(args)
        captured = capsys.readouterr()
        assert "-o" in captured.out

    def test_export_wrong_password(self, vault, capsys, monkeypatch):
        monkeypatch.setattr("getpass.getpass", lambda p="": "wrong-password")
        from jkey.pv.export import cmd_export

        args = type("Args", (), {"type": "totp", "output": None})
        cmd_export(args)
        captured = capsys.readouterr()
        assert "Incorrect password" in captured.out
