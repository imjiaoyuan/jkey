

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
    def test_remove_account(self, vault, capsys):
        import importlib

        remove_account = importlib.import_module("jkey.2fa.rm").remove_account
        from jkey.pv.core import load_recovery, load_totp, save_recovery, save_totp

        save_totp({"test@example.com": "JBSWY3DPEHPK3PXP"})
        save_recovery({"test@example.com": ["rc1"]})

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
