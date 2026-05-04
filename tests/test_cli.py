import sys

import pytest


class TestParser:
    """Test that argparse parses each subcommand correctly."""

    def _parser(self):
        """Build the parser (same as cli.main)."""
        import argparse

        parser = argparse.ArgumentParser(
            prog="jkey",
            description="Python library for password management and TOTP verification",
        )
        parser.add_argument("-v", "--version", action="version", version="jkey 0.0.0")
        sub = parser.add_subparsers(dest="command")

        p = sub.add_parser("2fa", help="Manage TOTP 2FA accounts")
        p2 = p.add_subparsers(dest="action")
        a = p2.add_parser("ls", help="List accounts and TOTP codes")
        a.add_argument("keyword", nargs="?", default=None)
        a = p2.add_parser("add", help="Import from QR code image")
        a.add_argument("image_path")
        a = p2.add_parser("rm", help="Remove account")
        a.add_argument("account")

        p = sub.add_parser("rc", help="Manage recovery codes")
        p2 = p.add_subparsers(dest="action")
        a = p2.add_parser("add", help="Import recovery codes from file")
        a.add_argument("file_path")
        a = p2.add_parser("ls", help="List recovery codes")
        a.add_argument("keyword", nargs="?", default=None)
        a = p2.add_parser("rm", help="Remove recovery codes")
        a.add_argument("account")

        p = sub.add_parser("pm", help="Manage passwords")
        p2 = p.add_subparsers(dest="action")
        a = p2.add_parser("ls", help="List stored passwords")
        a.add_argument("keyword", nargs="?", default=None)
        a = p2.add_parser("get", help="Generate random password")
        a.add_argument("-L", "--length", type=int, default=16)
        a.add_argument("--no-upper", action="store_true")
        a.add_argument("--no-lower", action="store_true")
        a.add_argument("--no-digits", action="store_true")
        a.add_argument("--no-symbols", action="store_true")
        a = p2.add_parser("add", help="Store password")
        a.add_argument("name")
        a = p2.add_parser("rm", help="Delete password")
        a.add_argument("name")

        p = sub.add_parser("pv", help="Manage encrypted vault")
        p2 = p.add_subparsers(dest="action")
        p2.add_parser("init", help="Initialize vault")
        p2.add_parser("unlock", help="Unlock vault")
        p2.add_parser("lock", help="Lock vault")
        p2.add_parser("set-pw", help="Set master password")
        e = p2.add_parser("encrypt", help="Encrypt a file")
        e.add_argument("input")
        e.add_argument("-o", "--output")
        d = p2.add_parser("decrypt", help="Decrypt a .jkey file")
        d.add_argument("input")
        d.add_argument("-o", "--output")
        x = p2.add_parser("export", help="Export plaintext data (re-enters master password)")
        x.add_argument("type", choices=["totp", "passwords", "recovery", "qr", "all"])
        x.add_argument("-o", "--output")

        return parser

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
