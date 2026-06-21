

class TestRcAdd:
    def test_add_from_file(self, vault, tmp_path, capsys):
        from jkey.rc.add import rc_add_file

        f = tmp_path / "google_codes.txt"
        f.write_text("code1\ncode2\ncode3\n")
        rc_add_file(str(f))
        captured = capsys.readouterr()
        assert "Imported 3 recovery codes for google_codes" in captured.out

    def test_add_file_not_found(self, vault, capsys):
        from jkey.rc.add import rc_add_file

        rc_add_file("/nonexistent/file.txt")
        captured = capsys.readouterr()
        assert "not found" in captured.out

    def test_add_empty_file(self, vault, tmp_path, capsys):
        from jkey.rc.add import rc_add_file

        f = tmp_path / "empty.txt"
        f.write_text("")
        rc_add_file(str(f))
        captured = capsys.readouterr()
        assert "No recovery codes found" in captured.out

    def test_add_file_only_whitespace(self, vault, tmp_path, capsys):
        from jkey.rc.add import rc_add_file

        f = tmp_path / "blank.txt"
        f.write_text("   \n\n  \n")
        rc_add_file(str(f))
        captured = capsys.readouterr()
        assert "No recovery codes found" in captured.out


class TestRcList:
    def test_list_empty(self, vault, capsys):
        from jkey.rc.ls import rc_list

        rc_list()
        captured = capsys.readouterr()
        assert "No recovery codes found" in captured.out

    def test_list_with_codes(self, vault, tmp_path, capsys):
        from jkey.rc.add import rc_add_file
        from jkey.rc.ls import rc_list

        f = tmp_path / "test_codes.txt"
        f.write_text("rc1\nrc2\n")
        rc_add_file(str(f))
        capsys.readouterr()

        rc_list()
        captured = capsys.readouterr()
        assert "rc1" in captured.out
        assert "rc2" in captured.out

    def test_list_with_keyword(self, vault, tmp_path, capsys):
        from jkey.rc.add import rc_add_file
        from jkey.rc.ls import rc_list

        for name in ("google", "github"):
            f = tmp_path / f"_{name}.txt"
            f.write_text("a\nb\n")
            rc_add_file(str(f))
            capsys.readouterr()

        rc_list("google")
        captured = capsys.readouterr()
        assert "google" in captured.out
        assert "github" not in captured.out

    def test_list_keyword_no_match(self, vault, tmp_path, capsys):
        from jkey.rc.add import rc_add_file
        from jkey.rc.ls import rc_list

        f = tmp_path / "myaccount.txt"
        f.write_text("rc1\nrc2\n")
        rc_add_file(str(f))
        capsys.readouterr()

        rc_list("nonexistent")
        captured = capsys.readouterr()
        assert "No recovery codes matching" in captured.out


class TestRcRemove:
    def test_remove_existing(self, vault, tmp_path, capsys):
        from jkey.rc.add import rc_add_file
        from jkey.rc.rm import rc_remove

        f = tmp_path / "test_file.txt"
        f.write_text("rc1\n")
        rc_add_file(str(f))
        capsys.readouterr()

        rc_remove("test_file")
        captured = capsys.readouterr()
        assert "Removed" in captured.out

    def test_remove_nonexistent(self, vault, capsys):
        from jkey.rc.rm import rc_remove

        rc_remove("nonexistent")
        captured = capsys.readouterr()
        assert "not found" in captured.out


class Test2faRemove:
    def test_remove_account(self, vault, capsys, monkeypatch):
        import importlib

        remove_account = importlib.import_module("jkey.2fa.rm").remove_account
        from jkey.pv.core import load_recovery, load_totp, save_recovery, save_totp

        save_totp({"test@example.com": "JBSWY3DPEHPK3PXP"})
        save_recovery({"test@example.com": ["rc1"]})

        monkeypatch.setattr("builtins.input", lambda p="": "y")
        remove_account("test@example.com")
        captured = capsys.readouterr()
        assert "Removed" in captured.out
        assert load_totp() == {}
        assert load_recovery() == {}

    def test_remove_nonexistent(self, vault, capsys):
        import importlib

        remove_account = importlib.import_module("jkey.2fa.rm").remove_account

        remove_account("nonexistent")
        captured = capsys.readouterr()
        assert "not found" in captured.out


class TestPmAdd:
    def test_add_password(self, vault, capsys, monkeypatch):
        from jkey.pm.add import add_password

        monkeypatch.setattr("getpass.getpass", lambda p="": "mysecret")
        add_password("myapp")
        captured = capsys.readouterr()
        assert "stored" in captured.out

        from jkey.pv.core import load_passwords

        assert load_passwords() == {"myapp": "mysecret"}

    def test_add_empty(self, vault, capsys, monkeypatch):
        from jkey.pm.add import add_password

        monkeypatch.setattr("getpass.getpass", lambda p="": "")
        add_password("myapp")
        captured = capsys.readouterr()
        assert "cannot be empty" in captured.out


class TestPmDelete:
    def test_delete_existing(self, vault, capsys, monkeypatch):
        from jkey.pm.add import add_password
        from jkey.pm.rm import delete_password

        monkeypatch.setattr("getpass.getpass", lambda p="": "secret")
        add_password("myapp")
        capsys.readouterr()

        delete_password("myapp")
        captured = capsys.readouterr()
        assert "deleted" in captured.out

        from jkey.pv.core import load_passwords

        assert load_passwords() == {}

    def test_delete_nonexistent(self, vault, capsys):
        from jkey.pm.rm import delete_password

        delete_password("nonexistent")
        captured = capsys.readouterr()
        assert "not found" in captured.out


class TestPmLsWarning:
    def test_warning_printed(self, vault, capsys, monkeypatch):
        from jkey.pm.add import add_password
        from jkey.pm.ls import list_passwords

        monkeypatch.setattr("getpass.getpass", lambda p="": "test123")
        add_password("testaccount")
        capsys.readouterr()
        list_passwords()
        captured = capsys.readouterr()
        assert "displaying stored passwords in plaintext" in captured.err


class Test2faRemoveWithRecovery:
    def test_confirm_yes(self, vault, capsys, monkeypatch):
        from jkey.pv.core import load_recovery, load_totp, save_recovery, save_totp

        save_totp({"test@example.com": "JBSWY3DPEHPK3PXP"})
        save_recovery({"test@example.com": ["rc1", "rc2"]})
        capsys.readouterr()

        monkeypatch.setattr("builtins.input", lambda p="": "y")
        import importlib

        remove_account = importlib.import_module("jkey.2fa.rm").remove_account

        remove_account("test@example.com")
        captured = capsys.readouterr()
        assert "Removed" in captured.out
        assert load_recovery() == {}
        assert load_totp() == {}

    def test_confirm_no(self, vault, capsys, monkeypatch):
        from jkey.pv.core import load_recovery, load_totp, save_recovery, save_totp

        save_totp({"test@example.com": "JBSWY3DPEHPK3PXP"})
        save_recovery({"test@example.com": ["rc1", "rc2"]})
        capsys.readouterr()

        monkeypatch.setattr("builtins.input", lambda p="": "n")
        import importlib as _il

        remove_account = _il.import_module("jkey.2fa.rm").remove_account

        remove_account("test@example.com")
        captured = capsys.readouterr()
        assert "Recovery codes kept" in captured.out
        assert load_recovery() == {"test@example.com": ["rc1", "rc2"]}
        assert load_totp() == {}

    def test_no_recovery_codes_no_prompt(self, vault, capsys, monkeypatch):
        from jkey.pv.core import load_totp, save_totp

        save_totp({"no_rc@example.com": "JBSWY3DPEHPK3PXP"})
        capsys.readouterr()

        # No need to mock input — no recovery codes means no prompt
        import importlib as _il2

        remove_account = _il2.import_module("jkey.2fa.rm").remove_account

        remove_account("no_rc@example.com")
        captured = capsys.readouterr()
        assert "Removed" in captured.out
        assert load_totp() == {}


class TestPmAddOverwrite:
    def test_overwrite_yes(self, vault, capsys, monkeypatch):
        from jkey.pm.add import add_password
        from jkey.pv.core import load_passwords

        inputs = iter(["mysecret1", "mysecret1", "o", "mysecret2", "mysecret2"])

        def mock_prompt(p=""):
            return next(inputs)

        monkeypatch.setattr("getpass.getpass", mock_prompt)
        monkeypatch.setattr("builtins.input", lambda p="": next(inputs))

        add_password("myapp")
        capsys.readouterr()
        add_password("myapp")
        captured = capsys.readouterr()
        assert "Password stored: myapp" in captured.out
        assert load_passwords() == {"myapp": "mysecret2"}

    def test_add_suffix(self, vault, capsys, monkeypatch):
        from jkey.pm.add import add_password
        from jkey.pv.core import load_passwords

        inputs = iter(["mysecret1", "mysecret1", "a", "v2", "mysecret2", "mysecret2"])

        def mock_prompt(p=""):
            return next(inputs)

        monkeypatch.setattr("getpass.getpass", mock_prompt)
        monkeypatch.setattr("builtins.input", lambda p="": next(inputs))

        add_password("myapp")
        capsys.readouterr()
        add_password("myapp")
        captured = capsys.readouterr()
        assert "Password stored: myapp-v2" in captured.out
        assert load_passwords() == {"myapp": "mysecret1", "myapp-v2": "mysecret2"}

    def test_cancel(self, vault, capsys, monkeypatch):
        from jkey.pm.add import add_password
        from jkey.pv.core import load_passwords

        inputs = iter(["mysecret1", "mysecret1", "c"])

        def mock_prompt(p=""):
            return next(inputs)

        monkeypatch.setattr("getpass.getpass", mock_prompt)
        monkeypatch.setattr("builtins.input", lambda p="": next(inputs))

        add_password("myapp")
        capsys.readouterr()
        add_password("myapp")
        captured = capsys.readouterr()
        assert "Password stored" not in captured.out
        assert load_passwords() == {"myapp": "mysecret1"}

    def test_passwords_do_not_match(self, vault, capsys, monkeypatch):
        from jkey.pm.add import add_password

        inputs = iter(["pass1", "pass2"])

        def mock_prompt(p=""):
            return next(inputs)

        monkeypatch.setattr("getpass.getpass", mock_prompt)
        add_password("newapp")
        captured = capsys.readouterr()
        assert "Passwords do not match" in captured.out


class TestRcAddOverwrite:
    def test_overwrite_confirm_yes(self, vault, tmp_path, capsys, monkeypatch):
        from jkey.pv.core import load_recovery
        from jkey.rc.add import rc_add_file

        f = tmp_path / "test_rc.txt"
        f.write_text("old1\nold2\n")
        rc_add_file(str(f))
        capsys.readouterr()

        f.write_text("new1\nnew2\n")
        monkeypatch.setattr("builtins.input", lambda p="": "y")
        rc_add_file(str(f))
        captured = capsys.readouterr()
        assert "Imported 2 recovery codes for test_rc" in captured.out
        assert load_recovery() == {"test_rc": ["new1", "new2"]}

    def test_overwrite_confirm_no(self, vault, tmp_path, capsys, monkeypatch):
        from jkey.pv.core import load_recovery
        from jkey.rc.add import rc_add_file

        f = tmp_path / "test_rc.txt"
        f.write_text("old1\nold2\n")
        rc_add_file(str(f))
        capsys.readouterr()

        monkeypatch.setattr("builtins.input", lambda p="": "n")
        rc_add_file(str(f))
        captured = capsys.readouterr()
        assert "Import cancelled" in captured.out
        assert load_recovery() == {"test_rc": ["old1", "old2"]}
