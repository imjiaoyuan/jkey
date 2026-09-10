import argparse
import importlib
import sys

from jkey.errors import JkeyError


def _call(mod_name, func_name, *args, **kwargs):
    return getattr(importlib.import_module(mod_name), func_name)(*args, **kwargs)


class _VersionAction(argparse.Action):
    """Print the installed version, importing importlib.metadata only when asked."""

    def __init__(self, option_strings, dest, **kwargs):
        super().__init__(option_strings, dest, nargs=0, **kwargs)

    def __call__(self, parser, namespace, values, option_string=None):
        from importlib.metadata import version

        parser._print_message(f"{parser.prog} {version('jkey')}\n", sys.stdout)
        parser.exit()


def _build_parser():
    parser = argparse.ArgumentParser(
        prog="jkey",
        description="Python library for password management and TOTP verification",
    )
    parser.add_argument(
        "-v", "--version", action=_VersionAction, default=argparse.SUPPRESS, help="show version and exit"
    )
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


def _noargs(_args):
    return ()


def _route(args, command, routes):
    if args.action not in routes:
        actions = "|".join(routes)
        print(f"Usage: jkey {command} {actions}", file=sys.stderr)
        sys.exit(1)
    mod_name, func_name, extract = routes[args.action]
    return _call(mod_name, func_name, *extract(args))


def _no_match(what: str, keyword: str | None) -> str:
    return f"No {what} matching '{keyword}'." if keyword else f"No {what} found."


def main():
    parser = _build_parser()
    args = parser.parse_args()
    if args.command is None:
        parser.print_help()
        sys.exit(1)

    try:
        if args.command == "2fa":
            _2fa(args)
        elif args.command == "rc":
            _rc(args)
        elif args.command == "pm":
            _pm(args)
        elif args.command == "pv":
            _pv(args)
    except JkeyError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        print(file=sys.stderr)
        sys.exit(130)


def _2fa(args):
    routes = {
        "ls": ("jkey.2fa.ls", "list_accounts", lambda a: (a.keyword,)),
        "add": ("jkey.2fa.add", "scan_and_add", lambda a: (a.image_path,)),
        "rm": ("jkey.2fa.rm", "remove_account", lambda a: (a.account,)),
    }
    result = _route(args, "2fa", routes)
    if args.action == "ls":
        if not result:
            print(_no_match("accounts", args.keyword))
        else:
            for name, code in result:
                print(f"{name}: {code}")


def _rc(args):
    routes = {
        "add": ("jkey.rc.add", "rc_add_file", lambda a: (a.file_path,)),
        "ls": ("jkey.rc.ls", "rc_list", lambda a: (a.keyword,)),
        "rm": ("jkey.rc.rm", "rc_remove", lambda a: (a.account,)),
    }
    result = _route(args, "rc", routes)
    if args.action == "ls":
        if not result:
            print(_no_match("recovery codes", args.keyword))
        else:
            for name, codes in result.items():
                print(f"{name}:")
                for code in codes:
                    print(f"  {code}")


def _pm(args):
    routes = {
        "ls": ("jkey.pm.ls", "list_passwords", lambda a: (a.keyword,)),
        "get": (
            "jkey.pm.get",
            "generate_password",
            lambda a: (a.length, not a.no_upper, not a.no_lower, not a.no_digits, not a.no_symbols),
        ),
        "add": ("jkey.pm.add", "add_password", lambda a: (a.name,)),
        "rm": ("jkey.pm.rm", "delete_password", lambda a: (a.name,)),
        "edit": ("jkey.pm.edit", "edit_password", lambda a: (a.name,)),
        "import": (
            "jkey.pm.import_csv",
            "import_csv",
            lambda a: (a.file, a.dry_run, a.duplicates, a.verbose, a.replace),
        ),
    }
    if args.action == "get":
        try:
            pwd = _route(args, "pm", routes)
        except ValueError as e:
            raise JkeyError(str(e)) from e
        print(pwd)
        return
    result = _route(args, "pm", routes)
    if args.action == "ls":
        if not result:
            print(_no_match("passwords", args.keyword))
        else:
            print("Warning: displaying stored passwords in plaintext.", file=sys.stderr)
            print("NAME: PASSWORD")
            for name, pw_val in result.items():
                print(f"{name}: {pw_val}")


def _pv(args):
    routes = {
        "init": ("jkey.pv.init", "cmd_init", _noargs),
        "unlock": ("jkey.pv.unlock", "cmd_unlock", _noargs),
        "lock": ("jkey.pv.lock", "cmd_lock", _noargs),
        "status": ("jkey.pv.status", "cmd_status", _noargs),
        "set-pw": ("jkey.pv.set_pw", "cmd_set_pw", _noargs),
        "encrypt": ("jkey.pv.encrypt", "encrypt_file", lambda a: (a.input, a.output)),
        "decrypt": ("jkey.pv.decrypt", "decrypt_file", lambda a: (a.input, a.output)),
        "export": ("jkey.pv.export", "cmd_export", lambda a: (a,)),
    }
    _route(args, "pv", routes)
