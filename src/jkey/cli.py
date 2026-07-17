import argparse
import importlib
import sys
from importlib.metadata import version


def _call(mod_name, func_name, *args, **kwargs):
    return getattr(importlib.import_module(mod_name), func_name)(*args, **kwargs)


def _build_parser():
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
    e = p2.add_parser("edit", help="Update an existing password")
    e.add_argument("name")
    i = p2.add_parser("import", help="Import passwords from browser CSV export")
    i.add_argument("file", help="Path to CSV file")
    i.add_argument("-n", "--dry-run", action="store_true", help="Preview without saving")
    i.add_argument("-v", "--verbose", action="store_true", help="Show skipped entries and reasons")
    i.add_argument("--replace", action="store_true", help="Replace all existing passwords before import")
    i.add_argument(
        "-d",
        "--duplicates",
        choices=["skip", "overwrite", "rename"],
        default="skip",
        help="How to handle duplicate entries (default: skip)",
    )

    p = sub.add_parser("pv", help="Manage encrypted vault")
    p2 = p.add_subparsers(dest="action")
    p2.add_parser("init", help="Initialize vault")
    p2.add_parser("unlock", help="Unlock vault")
    p2.add_parser("lock", help="Lock vault")
    p2.add_parser("status", help="Show vault status")
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


def main():
    parser = _build_parser()
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
    routes = {
        "ls": ("jkey.2fa.ls", "list_accounts", ("keyword",)),
        "add": ("jkey.2fa.add", "scan_and_add", ("image_path",)),
        "rm": ("jkey.2fa.rm", "remove_account", ("account",)),
    }
    if args.action not in routes:
        print("Usage: jkey 2fa ls|add|rm", file=sys.stderr)
        sys.exit(1)
    mod_name, func_name, attr_names = routes[args.action]
    call_args = tuple(getattr(args, name) for name in attr_names)
    result = _call(mod_name, func_name, *call_args)
    if args.action == "ls" and result is not None:
        if not result:
            msg = f"No accounts matching '{args.keyword}'." if args.keyword else "No 2FA accounts found."
            print(msg)
        else:
            for name, code in result:
                print(f"{name}: {code}")


def _rc(args):
    routes = {
        "add": ("jkey.rc.add", "rc_add_file", ("file_path",)),
        "ls": ("jkey.rc.ls", "rc_list", ("keyword",)),
        "rm": ("jkey.rc.rm", "rc_remove", ("account",)),
    }
    if args.action not in routes:
        print("Usage: jkey rc add|ls|rm", file=sys.stderr)
        sys.exit(1)
    mod_name, func_name, attr_names = routes[args.action]
    call_args = tuple(getattr(args, name) for name in attr_names)
    result = _call(mod_name, func_name, *call_args)
    if args.action == "ls" and result is not None:
        if not result:
            msg = f"No recovery codes matching '{args.keyword}'." if args.keyword else "No recovery codes found."
            print(msg)
        else:
            for name, codes in result.items():
                print(f"{name}:")
                for code in codes:
                    print(f"  {code}")


def _pm(args):
    a = args.action
    if a == "ls":
        result = _call("jkey.pm.ls", "list_passwords", args.keyword)
        if result is not None:
            if not result:
                msg = f"No passwords matching '{args.keyword}'." if args.keyword else "No stored passwords found."
                print(msg)
            else:
                print("Warning: displaying stored passwords in plaintext.", file=sys.stderr)
                print("SITE (USERNAME): PASSWORD")
                for name, pw_val in result.items():
                    print(f"{name}: {pw_val}")
    elif a == "get":
        try:
            pwd = _call(
                "jkey.pm.get",
                "generate_password",
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
        _call("jkey.pm.add", "add_password", args.name)
    elif a == "rm":
        _call("jkey.pm.rm", "delete_password", args.name)
    elif a == "edit":
        _call("jkey.pm.edit", "edit_password", args.name)
    elif a == "import":
        _call(
            "jkey.pm.import_csv",
            "import_csv",
            args.file,
            dry_run=args.dry_run,
            duplicates=args.duplicates,
            verbose=args.verbose,
            replace=args.replace,
        )
    else:
        print("Usage: jkey pm ls|get|add|rm|edit|import", file=sys.stderr)
        sys.exit(1)


def _pv(args):
    routes = {
        "init": ("jkey.pv.init", "cmd_init", ()),
        "unlock": ("jkey.pv.unlock", "cmd_unlock", ()),
        "lock": ("jkey.pv.lock", "cmd_lock", ()),
        "status": ("jkey.pv.status", "cmd_status", ()),
        "set-pw": ("jkey.pv.set_pw", "cmd_set_pw", ()),
    }
    a = args.action
    if a in routes:
        _call(routes[a][0], routes[a][1], *routes[a][2])
    elif a == "encrypt":
        _call("jkey.pv.encrypt", "encrypt_file", args.input, args.output)
    elif a == "decrypt":
        _call("jkey.pv.decrypt", "decrypt_file", args.input, args.output)
    elif a == "export":
        _call("jkey.pv.export", "cmd_export", args)
    else:
        print("Usage: jkey pv init|unlock|lock|status|set-pw|encrypt|decrypt|export", file=sys.stderr)
        sys.exit(1)
