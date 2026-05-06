import argparse
import sys
from importlib.metadata import version


def main():
    parser = argparse.ArgumentParser(
        prog="jkey",
        description="Python library for password management and TOTP verification",
    )
    parser.add_argument("-v", "--version", action="version", version=f"%(prog)s {version('jkey')}")
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

    args = parser.parse_args()
    if args.command is None:
        parser.print_help()
        sys.exit(1)

    if args.command == "2fa":
        _2fa(args)
    elif args.command == "rc":
        _rc(args)
    elif args.command == "pm":
        _pm(args)
    elif args.command == "pv":
        _pv(args)


def _2fa(args):
    import importlib

    a = args.action
    if a == "ls":
        importlib.import_module("jkey.2fa.ls").list_accounts(args.keyword)
    elif a == "add":
        importlib.import_module("jkey.2fa.add").scan_and_add(args.image_path)
    elif a == "rm":
        importlib.import_module("jkey.2fa.rm").remove_account(args.account)
    else:
        print("Usage: jkey 2fa ls|add|rm")


def _rc(args):
    import importlib

    a = args.action
    if a == "add":
        importlib.import_module("jkey.rc.add").rc_add_file(args.file_path)
    elif a == "ls":
        importlib.import_module("jkey.rc.ls").rc_list(args.keyword)
    elif a == "rm":
        importlib.import_module("jkey.rc.rm").rc_remove(args.account)
    else:
        print("Usage: jkey rc add|ls|rm")


def _pm(args):
    import importlib

    a = args.action
    if a == "ls":
        importlib.import_module("jkey.pm.ls").list_passwords(args.keyword)
    elif a == "get":
        try:
            pwd = importlib.import_module("jkey.pm.get").generate_password(
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
    elif a == "add":
        importlib.import_module("jkey.pm.add").add_password(args.name)
    elif a == "rm":
        importlib.import_module("jkey.pm.rm").delete_password(args.name)
    else:
        print("Usage: jkey pm ls|get|add|rm")


def _pv(args):
    import importlib

    a = args.action
    if a == "init":
        importlib.import_module("jkey.pv.init").cmd_init()
    elif a == "unlock":
        importlib.import_module("jkey.pv.unlock").cmd_unlock()
    elif a == "lock":
        importlib.import_module("jkey.pv.lock").cmd_lock()
    elif a == "set-pw":
        importlib.import_module("jkey.pv.set_pw").cmd_set_pw()
    elif a == "encrypt":
        importlib.import_module("jkey.pv.encrypt").encrypt_file(args.input, args.output)
    elif a == "decrypt":
        importlib.import_module("jkey.pv.decrypt").decrypt_file(args.input, args.output)
    elif a == "export":
        importlib.import_module("jkey.pv.export").cmd_export(args)
    else:
        print("Usage: jkey pv init|unlock|lock|set-pw|encrypt|decrypt|export")
