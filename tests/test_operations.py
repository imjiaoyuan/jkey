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

        result = rc_list()
        assert result == {}

    def test_list_with_codes(self, vault, tmp_path, capsys):
        from jkey.rc.add import rc_add_file
        from jkey.rc.ls import rc_list

        f = tmp_path / "test_codes.txt"
        f.write_text("rc1\nrc2\n")
        rc_add_file(str(f))
        capsys.readouterr()

        result = rc_list()
        assert "test_codes" in result
        assert result["test_codes"] == ["rc1", "rc2"]

    def test_list_with_keyword(self, vault, tmp_path, capsys):
        from jkey.rc.add import rc_add_file
        from jkey.rc.ls import rc_list

        for name in ("google", "github"):
            f = tmp_path / f"_{name}.txt"
            f.write_text("a\nb\n")
            rc_add_file(str(f))
            capsys.readouterr()

        result = rc_list("google")
        assert "_google" in result
        assert "_github" not in result

    def test_list_keyword_no_match(self, vault, tmp_path, capsys):
        from jkey.rc.add import rc_add_file
        from jkey.rc.ls import rc_list

        f = tmp_path / "myaccount.txt"
        f.write_text("rc1\nrc2\n")
        rc_add_file(str(f))
        capsys.readouterr()

        result = rc_list("nonexistent")
        assert result == {}


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
    def test_list_returns_data(self, vault, capsys, monkeypatch):
        from jkey.pm.add import add_password
        from jkey.pm.ls import list_passwords

        monkeypatch.setattr("getpass.getpass", lambda p="": "test123")
        add_password("testaccount")
        capsys.readouterr()
        result = list_passwords()
        assert "testaccount" in result
        assert result["testaccount"] == "test123"

    def test_list_keyword_filter(self, vault, capsys, monkeypatch):
        from jkey.pm.add import add_password
        from jkey.pm.ls import list_passwords

        monkeypatch.setattr("getpass.getpass", lambda p="": "test123")
        add_password("GitHub")
        capsys.readouterr()
        result = list_passwords("hub")
        assert "GitHub" in result
        assert "GitHub" not in list_passwords("gitlab")


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


class TestPmEdit:
    def test_edit_existing(self, vault, capsys, monkeypatch):
        from jkey.pm.add import add_password
        from jkey.pm.edit import edit_password
        from jkey.pv.core import load_passwords

        monkeypatch.setattr("getpass.getpass", lambda p="": "oldsecret")
        add_password("myapp")
        capsys.readouterr()

        monkeypatch.setattr("getpass.getpass", lambda p="": "newsecret")
        edit_password("myapp")
        captured = capsys.readouterr()
        assert "Password updated: myapp" in captured.out
        assert load_passwords() == {"myapp": "newsecret"}

    def test_edit_nonexistent(self, vault, capsys):
        from jkey.pm.edit import edit_password

        edit_password("nonexistent")
        captured = capsys.readouterr()
        assert "not found" in captured.out

    def test_edit_empty_password(self, vault, capsys, monkeypatch):
        from jkey.pm.add import add_password
        from jkey.pm.edit import edit_password
        from jkey.pv.core import load_passwords

        monkeypatch.setattr("getpass.getpass", lambda p="": "oldsecret")
        add_password("myapp")
        capsys.readouterr()

        monkeypatch.setattr("getpass.getpass", lambda p="": "")
        edit_password("myapp")
        captured = capsys.readouterr()
        assert "cannot be empty" in captured.out
        assert load_passwords() == {"myapp": "oldsecret"}

    def test_edit_mismatch(self, vault, capsys, monkeypatch):
        from jkey.pm.add import add_password
        from jkey.pm.edit import edit_password
        from jkey.pv.core import load_passwords

        monkeypatch.setattr("getpass.getpass", lambda p="": "oldsecret")
        add_password("myapp")
        capsys.readouterr()

        inputs = iter(["newpass1", "newpass2"])

        def mock_prompt(p=""):
            return next(inputs)

        monkeypatch.setattr("getpass.getpass", mock_prompt)
        edit_password("myapp")
        captured = capsys.readouterr()
        assert "do not match" in captured.out
        assert load_passwords() == {"myapp": "oldsecret"}


class TestPmImportCsv:

    def test_chrome_csv(self, vault, tmp_path, capsys):
        from jkey.pm.import_csv import import_csv
        from jkey.pv.core import load_passwords

        f = tmp_path / "chrome.csv"
        f.write_text("name,url,username,password\nGoogle,https://google.com,user1,pass1\nGitHub,https://github.com,user2,pass2\n")
        import_csv(str(f))
        captured = capsys.readouterr()
        assert "Imported 2" in captured.out
        assert "Google (user1)" in captured.out
        assert "GitHub (user2)" in captured.out
        assert load_passwords() == {"Google (user1)": "pass1", "GitHub (user2)": "pass2"}

    def test_same_site_multiple_accounts(self, vault, tmp_path, capsys):
        from jkey.pm.import_csv import import_csv
        from jkey.pv.core import load_passwords

        f = tmp_path / "multi.csv"
        f.write_text("name,url,username,password\nGoogle,https://google.com,alice@gmail.com,pass1\nGoogle,https://google.com,bob@gmail.com,pass2\n")
        import_csv(str(f))
        capsys.readouterr()
        data = load_passwords()
        assert len(data) == 2
        assert "Google (alice@gmail.com)" in data
        assert "Google (bob@gmail.com)" in data

    def test_no_username_column(self, vault, tmp_path, capsys):
        from jkey.pm.import_csv import import_csv
        from jkey.pv.core import load_passwords

        f = tmp_path / "nouser.csv"
        f.write_text("name,url,password\nGitHub,https://github.com,p1\n")
        import_csv(str(f))
        capsys.readouterr()
        assert load_passwords() == {"GitHub": "p1"}

    def test_no_name_column_fallback_to_url(self, vault, tmp_path, capsys):
        from jkey.pm.import_csv import import_csv
        from jkey.pv.core import load_passwords

        f = tmp_path / "n.csv"
        f.write_text("url,username,password\nhttps://example.com,u1,p1\nhttps://test.org,u2,p2\n")
        import_csv(str(f))
        capsys.readouterr()
        data = load_passwords()
        assert "example.com (u1)" in data
        assert "test.org (u2)" in data

    def test_empty_name_fallback_to_url(self, vault, tmp_path, capsys):
        from jkey.pm.import_csv import import_csv
        from jkey.pv.core import load_passwords

        f = tmp_path / "empty_name.csv"
        f.write_text("name,url,username,password\n,https://site.com,u1,p1\n")
        import_csv(str(f))
        capsys.readouterr()
        assert "site.com (u1)" in load_passwords()

    def test_empty_name_and_url_fallback_to_username(self, vault, tmp_path, capsys):
        from jkey.pm.import_csv import import_csv
        from jkey.pv.core import load_passwords

        f = tmp_path / "no_name_url.csv"
        f.write_text("name,url,username,password\n,,myuser,p1\n")
        import_csv(str(f))
        capsys.readouterr()
        assert load_passwords() == {"myuser": "p1"}

    def test_last_resort_name(self, vault, tmp_path, capsys):
        from jkey.pm.import_csv import import_csv
        from jkey.pv.core import load_passwords

        f = tmp_path / "all_empty.csv"
        f.write_text("name,url,username,password\n,,,p1\n")
        import_csv(str(f))
        capsys.readouterr()
        assert "entry-1" in load_passwords()

    def test_url_without_scheme(self, vault, tmp_path, capsys):
        from jkey.pm.import_csv import import_csv
        from jkey.pv.core import load_passwords

        f = tmp_path / "noscheme.csv"
        f.write_text("url,username,password\nexample.com/path,u1,p1\n")
        import_csv(str(f))
        capsys.readouterr()
        assert "example.com (u1)" in load_passwords()

    def test_firefox_csv(self, vault, tmp_path, capsys):
        from jkey.pm.import_csv import import_csv
        from jkey.pv.core import load_passwords

        f = tmp_path / "firefox.csv"
        f.write_text("url,username,password\nhttps://firefox.site.com,u1,p1\n")
        import_csv(str(f))
        capsys.readouterr()
        assert "firefox.site.com (u1)" in load_passwords()

    def test_safari_csv(self, vault, tmp_path, capsys):
        from jkey.pm.import_csv import import_csv
        from jkey.pv.core import load_passwords

        f = tmp_path / "safari.csv"
        f.write_text("Title,URL,Username,Password\nMy Site,https://safari.example.com,user1,pass1\n")
        import_csv(str(f))
        capsys.readouterr()
        assert load_passwords() == {"My Site (user1)": "pass1"}

    def test_bitwarden_csv(self, vault, tmp_path, capsys):
        from jkey.pm.import_csv import import_csv
        from jkey.pv.core import load_passwords

        f = tmp_path / "bitwarden.csv"
        f.write_text(
            "folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp\n"
            ",,login,MyLogin,,,0,https://bw.example.com,bwuser,bwpass,\n"
        )
        import_csv(str(f))
        capsys.readouterr()
        assert load_passwords() == {"MyLogin (bwuser)": "bwpass"}

    def test_1password_csv(self, vault, tmp_path, capsys):
        from jkey.pm.import_csv import import_csv
        from jkey.pv.core import load_passwords

        f = tmp_path / "1p.csv"
        f.write_text("title,url,username,password\nOnePass,https://1p.example.com,opuser,oppass\n")
        import_csv(str(f))
        capsys.readouterr()
        assert load_passwords() == {"OnePass (opuser)": "oppass"}

    def test_dashlane_csv(self, vault, tmp_path, capsys):
        from jkey.pm.import_csv import import_csv
        from jkey.pv.core import load_passwords

        f = tmp_path / "dashlane.csv"
        f.write_text("username,username2,username3,title,password,note,url,category,otpSecret\n"
                     "dluser,,,DashlaneSite,dlpass,,https://dl.example.com,,\n")
        import_csv(str(f))
        capsys.readouterr()
        assert load_passwords() == {"DashlaneSite (dluser)": "dlpass"}

    def test_lastpass_csv(self, vault, tmp_path, capsys):
        from jkey.pm.import_csv import import_csv
        from jkey.pv.core import load_passwords

        f = tmp_path / "lastpass.csv"
        f.write_text("url,username,password,totp,extra,name,grouping,fav\n"
                     "https://lp.example.com,lpuser,lppass,,,,,\n")
        import_csv(str(f))
        capsys.readouterr()
        assert "lp.example.com (lpuser)" in load_passwords()

    def test_nordpass_csv(self, vault, tmp_path, capsys):
        from jkey.pm.import_csv import import_csv
        from jkey.pv.core import load_passwords

        f = tmp_path / "nordpass.csv"
        f.write_text("name,url,username,password,note\nNP Site,https://np.example.com,npuser,nppass,\n")
        import_csv(str(f))
        capsys.readouterr()
        assert load_passwords() == {"NP Site (npuser)": "nppass"}

    def test_duplicates_skip(self, vault, tmp_path, capsys):
        from jkey.pm.import_csv import import_csv
        from jkey.pv.core import load_passwords, save_passwords

        save_passwords({"Google (user1)": "oldpass"})
        capsys.readouterr()

        f = tmp_path / "dup.csv"
        f.write_text("name,url,username,password\nGoogle,https://google.com,user1,newpass\n")
        import_csv(str(f), duplicates="skip")
        captured = capsys.readouterr()
        assert "1 duplicate" in captured.out
        assert load_passwords() == {"Google (user1)": "oldpass"}

    def test_duplicates_overwrite(self, vault, tmp_path, capsys):
        from jkey.pm.import_csv import import_csv
        from jkey.pv.core import load_passwords, save_passwords

        save_passwords({"Google (user1)": "oldpass"})
        capsys.readouterr()

        f = tmp_path / "dup.csv"
        f.write_text("name,url,username,password\nGoogle,https://google.com,user1,newpass\n")
        import_csv(str(f), duplicates="overwrite")
        captured = capsys.readouterr()
        assert "Overwritten 1" in captured.out
        assert load_passwords() == {"Google (user1)": "newpass"}

    def test_duplicates_rename(self, vault, tmp_path, capsys):
        from jkey.pm.import_csv import import_csv
        from jkey.pv.core import load_passwords, save_passwords

        save_passwords({"Google (user1)": "oldpass"})
        capsys.readouterr()

        f = tmp_path / "dup.csv"
        f.write_text("name,url,username,password\nGoogle,https://google.com,user1,newpass\n")
        import_csv(str(f), duplicates="rename")
        captured = capsys.readouterr()
        assert "Imported 1" in captured.out
        data = load_passwords()
        assert data["Google (user1)"] == "oldpass"
        assert data["Google (user1)-2"] == "newpass"

    def test_dry_run(self, vault, tmp_path, capsys):
        from jkey.pm.import_csv import import_csv
        from jkey.pv.core import load_passwords

        f = tmp_path / "dry.csv"
        f.write_text("name,url,username,password\nA,https://a.com,u1,p1\nB,https://b.com,u2,p2\n")
        import_csv(str(f), dry_run=True)
        captured = capsys.readouterr()
        assert "2 new" in captured.out
        assert "Preview" in captured.out
        assert load_passwords() == {}

    def test_file_not_found(self, vault, capsys):
        from jkey.pm.import_csv import import_csv

        import_csv("/nonexistent/passwords.csv")
        captured = capsys.readouterr()
        assert "not found" in captured.err

    def test_empty_csv(self, vault, tmp_path, capsys):
        from jkey.pm.import_csv import import_csv

        f = tmp_path / "empty.csv"
        f.write_text("")
        import_csv(str(f))
        captured = capsys.readouterr()
        assert "empty" in captured.err

    def test_headers_only(self, vault, tmp_path, capsys):
        from jkey.pm.import_csv import import_csv

        f = tmp_path / "headers.csv"
        f.write_text("name,url,username,password\n")
        import_csv(str(f))
        captured = capsys.readouterr()
        assert "no data rows" in captured.err

    def test_no_password_column(self, vault, tmp_path, capsys):
        from jkey.pm.import_csv import import_csv

        f = tmp_path / "no_pw.csv"
        f.write_text("name,url,username\nA,https://a.com,u1\n")
        import_csv(str(f))
        captured = capsys.readouterr()
        assert "password column" in captured.err

    def test_skips_empty_passwords(self, vault, tmp_path, capsys):
        from jkey.pm.import_csv import import_csv
        from jkey.pv.core import load_passwords

        f = tmp_path / "skip_empty.csv"
        f.write_text("name,url,username,password\nA,https://a.com,u1,\nB,https://b.com,u2,p2\n")
        import_csv(str(f))
        captured = capsys.readouterr()
        assert "Imported 1" in captured.out
        assert "1 empty password" in captured.out
        assert "B (u2)" in load_passwords()

    def test_utf8_bom(self, vault, tmp_path, capsys):
        from jkey.pm.import_csv import import_csv
        from jkey.pv.core import load_passwords

        f = tmp_path / "bom.csv"
        f.write_bytes(b"\xef\xbb\xbfname,url,username,password\nBOM,https://bom.com,u1,p1\n")
        import_csv(str(f))
        capsys.readouterr()
        assert "BOM (u1)" in load_passwords()

    def test_replace(self, vault, tmp_path, capsys):
        from jkey.pm.import_csv import import_csv
        from jkey.pv.core import load_passwords, save_passwords

        save_passwords({"old-entry": "oldpass", "another": "x"})
        capsys.readouterr()

        f = tmp_path / "replace.csv"
        f.write_text("name,url,username,password\nNew,https://n.com,u1,p1\n")
        import_csv(str(f), replace=True)
        captured = capsys.readouterr()
        assert "Imported 1" in captured.out
        data = load_passwords()
        assert "New (u1)" in data
        assert "old-entry" not in data
        assert "another" not in data

    def test_no_entries_to_import(self, vault, tmp_path, capsys):
        from jkey.pm.import_csv import import_csv

        f = tmp_path / "all_skip.csv"
        f.write_text("name,url,username,password\n,,,\n,,,\n")
        import_csv(str(f))
        captured = capsys.readouterr()
        assert "No new entries" in captured.out
