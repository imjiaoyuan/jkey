import sys

import pytest


class TestParser:
    """Test that argparse parses each subcommand correctly."""

    def _parser(self):
        from jkey.cli import _build_parser

        return _build_parser()

    def test_2fa_ls(self):
        parser = self._parser()
        args = parser.parse_args(["2fa", "ls"])
        assert args.command == "2fa"
        assert args.action == "ls"
        assert args.keyword is None

    def test_2fa_ls_with_keyword(self):
        parser = self._parser()
        args = parser.parse_args(["2fa", "ls", "google"])
        assert args.action == "ls"
        assert args.keyword == "google"

    def test_2fa_add(self):
        parser = self._parser()
        args = parser.parse_args(["2fa", "add", "/path/to/qr.png"])
        assert args.action == "add"
        assert args.image_path == "/path/to/qr.png"

    def test_2fa_rm(self):
        parser = self._parser()
        args = parser.parse_args(["2fa", "rm", "test@example.com"])
        assert args.action == "rm"
        assert args.account == "test@example.com"

    def test_rc_ls(self):
        parser = self._parser()
        args = parser.parse_args(["rc", "ls"])
        assert args.command == "rc"
        assert args.action == "ls"

    def test_rc_add(self):
        parser = self._parser()
        args = parser.parse_args(["rc", "add", "codes.txt"])
        assert args.action == "add"
        assert args.file_path == "codes.txt"

    def test_rc_rm(self):
        parser = self._parser()
        args = parser.parse_args(["rc", "rm", "example"])
        assert args.action == "rm"
        assert args.account == "example"

    def test_pm_ls(self):
        parser = self._parser()
        args = parser.parse_args(["pm", "ls"])
        assert args.command == "pm"
        assert args.action == "ls"

    def test_pm_ls_keyword(self):
        parser = self._parser()
        args = parser.parse_args(["pm", "ls", "github"])
        assert args.keyword == "github"

    def test_pm_get_default(self):
        parser = self._parser()
        args = parser.parse_args(["pm", "get"])
        assert args.action == "get"
        assert args.length == 16
        assert not args.no_upper

    def test_pm_get_custom(self):
        parser = self._parser()
        args = parser.parse_args(["pm", "get", "-L", "32", "--no-symbols", "--no-digits"])
        assert args.length == 32
        assert args.no_symbols is True
        assert args.no_digits is True
        assert not args.no_upper
        assert not args.no_lower

    def test_pm_add(self):
        parser = self._parser()
        args = parser.parse_args(["pm", "add", "myapp"])
        assert args.action == "add"
        assert args.name == "myapp"

    def test_pm_rm(self):
        parser = self._parser()
        args = parser.parse_args(["pm", "rm", "myapp"])
        assert args.action == "rm"
        assert args.name == "myapp"

    def test_pm_edit(self):
        parser = self._parser()
        args = parser.parse_args(["pm", "edit", "myapp"])
        assert args.action == "edit"
        assert args.name == "myapp"

    def test_pm_import_default(self):
        parser = self._parser()
        args = parser.parse_args(["pm", "import", "passwords.csv"])
        assert args.action == "import"
        assert args.file == "passwords.csv"
        assert args.dry_run is False
        assert args.duplicates == "skip"

    def test_pm_import_flags(self):
        parser = self._parser()
        args = parser.parse_args(["pm", "import", "p.csv", "-n", "-d", "overwrite"])
        assert args.dry_run is True
        assert args.duplicates == "overwrite"

    def test_pv_init(self):
        parser = self._parser()
        args = parser.parse_args(["pv", "init"])
        assert args.command == "pv"
        assert args.action == "init"

    def test_pv_unlock(self):
        parser = self._parser()
        args = parser.parse_args(["pv", "unlock"])
        assert args.action == "unlock"

    def test_pv_lock(self):
        parser = self._parser()
        args = parser.parse_args(["pv", "lock"])
        assert args.action == "lock"

    def test_pv_set_pw(self):
        parser = self._parser()
        args = parser.parse_args(["pv", "set-pw"])
        assert args.action == "set-pw"

    def test_pv_encrypt(self):
        parser = self._parser()
        args = parser.parse_args(["pv", "encrypt", "file.txt", "-o", "out.jkey"])
        assert args.action == "encrypt"
        assert args.input == "file.txt"
        assert args.output == "out.jkey"

    def test_pv_decrypt(self):
        parser = self._parser()
        args = parser.parse_args(["pv", "decrypt", "file.jkey"])
        assert args.action == "decrypt"
        assert args.input == "file.jkey"
        assert args.output is None

    def test_pv_export_totp(self):
        parser = self._parser()
        args = parser.parse_args(["pv", "export", "totp"])
        assert args.action == "export"
        assert args.type == "totp"

    def test_pv_export_all(self):
        parser = self._parser()
        args = parser.parse_args(["pv", "export", "all", "-o", "/tmp/out"])
        assert args.type == "all"
        assert args.output == "/tmp/out"

    def test_no_command_shows_help(self):
        """When no command is given, command is None."""
        parser = self._parser()
        args = parser.parse_args([])
        assert args.command is None


class TestMainDispatch:
    def test_main_no_command(self, vault_dir, monkeypatch):
        """main() with no command should print help and exit 1."""

        monkeypatch.setattr(sys, "argv", ["jkey"])
        from jkey.cli import main

        with pytest.raises(SystemExit) as exc:
            main()
        assert exc.value.code == 1

    def test_main_2fa_help(self, capsys, monkeypatch):

        monkeypatch.setattr(sys, "argv", ["jkey", "2fa", "--help"])
        from jkey.cli import main

        with pytest.raises(SystemExit):
            main()
        captured = capsys.readouterr()
        assert "ls" in captured.out or "add" in captured.out
