import argparse
import importlib
import sys

from jkey.__about__ import __version__
from jkey.pm.core import (
    add_password,
    delete_password,
    import_from_csv,
    list_passwords,
    show_password,
)
from jkey.pm.gen import generate_password
from jkey.pv.core import cmd_init, cmd_lock, cmd_set_pw, cmd_unlock, decrypt_file, encrypt_file
from jkey.pv.export import cmd_export


def main():
    parser = argparse.ArgumentParser(
        prog="jkey",
        description="Python library for password management and TOTP verification",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command")

    p = sub.add_parser("2fa", help="Manage TOTP 2FA accounts")
    p2 = p.add_subparsers(dest="action")
    a = p2.add_parser("ls", help="List accounts and TOTP codes")
    a.add_argument("keyword", nargs="?", default=None)
    a = p2.add_parser("get", help="Show TOTP code")
    a.add_argument("account")
    a = p2.add_parser("add", help="Add account")
    a.add_argument("name")
    a.add_argument("secret")
    a.add_argument("--recovery")
    a = p2.add_parser("qr", help="Import from QR code")
    a.add_argument("image_path")
    a.add_argument("--recovery")
    a = p2.add_parser("rm", help="Remove account")
    a.add_argument("account")

    p = sub.add_parser("pm", help="Manage passwords")
    p2 = p.add_subparsers(dest="action")
    g = p2.add_parser("gen", help="Generate random password")
    g.add_argument("-L", "--length", type=int, default=16)
    g.add_argument("--no-upper", action="store_true")
    g.add_argument("--no-lower", action="store_true")
    g.add_argument("--no-digits", action="store_true")
    g.add_argument("--no-symbols", action="store_true")
    a = p2.add_parser("ls", help="List stored passwords")
    a.add_argument("keyword", nargs="?", default=None)
    a = p2.add_parser("get", help="Show stored password")
    a.add_argument("name")
    a = p2.add_parser("add", help="Store password")
    a.add_argument("name")
    a = p2.add_parser("rm", help="Delete password")
    a.add_argument("name")
    a = p2.add_parser("import", help="Import from CSV")
    a.add_argument("csv_path")

    p = sub.add_parser("pv", help="Manage encrypted vault (passwd vault)")
    p2 = p.add_subparsers(dest="action")
    p2.add_parser("init", help="Initialize vault")
    p2.add_parser("unlock", help="Unlock vault")
    p2.add_parser("lock", help="Lock vault")
    p2.add_parser("set-pw", help="Set master password")
    e = p2.add_parser("encrypt", help="Encrypt a file")
    e.add_argument("input")
    e.add_argument("-o", "--output", help="Output .jkey path")
    d = p2.add_parser("decrypt", help="Decrypt a .jkey file")
    d.add_argument("input")
    d.add_argument("-o", "--output", help="Output file path")
    x = p2.add_parser("export", help="Export plaintext data (re-enters master password)")
    x.add_argument("type", choices=["totp", "passwords", "recovery", "qr", "all"])
    x.add_argument("-o", "--output", help="Output path (file or directory)")

    args = parser.parse_args()
    if args.command is None:
        parser.print_help()
        sys.exit(1)

    if args.command == "2fa":
        _2fa(args)
    elif args.command == "pm":
        _pm(args)
    elif args.command == "pv":
        _pv(args)


def _2fa(args):
    core = importlib.import_module("jkey.2fa.core")
    a = args.action
    if a == "ls":
        core.list_accounts(args.keyword)
    elif a == "get":
        core.show_code(args.account)
    elif a == "add":
        core.add_account(args.name, args.secret, args.recovery)
    elif a == "qr":
        qr_mod = importlib.import_module("jkey.2fa.qr")
        qr_mod.scan_and_add(args.image_path, args.recovery)
    elif a == "rm":
        core.remove_account(args.account)
    else:
        print("Usage: jkey 2fa ls|get|add|qr|rm")


def _pm(args):
    a = args.action
    if a == "gen":
        try:
            pwd = generate_password(
                length=args.length,
                uppercase=not args.no_upper,
                lowercase=not args.no_lower,
                digits=not args.no_digits,
                symbols=not args.no_symbols,
            )
            print(pwd)
        except ValueError as e:
            print(f"Error: {e}")
            sys.exit(1)
    elif a == "ls":
        list_passwords(args.keyword)
    elif a == "get":
        show_password(args.name)
    elif a == "add":
        add_password(args.name)
    elif a == "rm":
        delete_password(args.name)
    elif a == "import":
        import_from_csv(args.csv_path)
    else:
        print("Usage: jkey pm gen|ls|get|add|rm|import")


def _pv(args):
    a = args.action
    if a == "init":
        cmd_init()
    elif a == "unlock":
        cmd_unlock()
    elif a == "lock":
        cmd_lock()
    elif a == "set-pw":
        cmd_set_pw()
    elif a == "encrypt":
        encrypt_file(args.input, args.output)
    elif a == "decrypt":
        decrypt_file(args.input, args.output)
    elif a == "export":
        cmd_export(args)
    else:
        print("Usage: jkey pv init|unlock|lock|set-pw|encrypt|decrypt|export")
