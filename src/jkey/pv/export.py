import csv
import getpass
import io
import os

from jkey.errors import JkeyError
from jkey.pv.core import (
    ensure_unlocked,
    get_session_password,
    list_qr_images,
    load_passwords,
    load_qr_image,
    load_recovery,
    load_totp,
    password_from_env,
    write_secure_bytes,
    write_secure_text,
)


def _export_totp(output: str | None) -> None:
    data = load_totp()
    out = _build_totp_content(data)
    if output:
        write_secure_text(output, out + "\n", atomic=True)
        print(f"Exported TOTP secrets to {output}")
    else:
        print(out)


def _build_totp_content(data: dict) -> str:
    import json

    return json.dumps(data, indent=4, ensure_ascii=False)


def _export_passwords(output: str | None) -> None:
    data = load_passwords()
    out = _build_passwords_content(data)
    if output:
        write_secure_text(output, out, newline="", atomic=True)
        print(f"Exported passwords to {output}")
    else:
        print(out, end="")


def _build_passwords_content(data: dict) -> str:
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["name", "password"])
    for name, pw_val in sorted(data.items()):
        w.writerow([name, pw_val])
    return buf.getvalue()


def _export_recovery(output: str | None) -> None:
    data = load_recovery()
    out = _build_recovery_content(data)
    if output:
        write_secure_text(output, out + "\n", atomic=True)
        print(f"Exported recovery codes to {output}")
    else:
        print(out)


def _build_recovery_content(data: dict) -> str:
    lines = []
    for account in sorted(data.keys()):
        lines.append(f"Account: {account}")
        for code in data[account]:
            lines.append(f"  {code}")
        lines.append("")
    return "\n".join(lines)


def _export_qr(output_dir: str) -> None:
    os.makedirs(output_dir, mode=0o700, exist_ok=True)
    names = list_qr_images()
    if not names:
        print("No QR images found.")
        return
    for name in names:
        img = load_qr_image(name)
        if img:
            path = os.path.join(output_dir, f"{name}.jpg")
            write_secure_bytes(path, img, atomic=True)
    print(f"Exported {len(names)} QR images to {output_dir}")


def cmd_export(args):
    ensure_unlocked()

    session_pw = get_session_password()
    pw = password_from_env()
    if pw != session_pw:
        try:
            pw = getpass.getpass("Confirm master password to export: ")
        except (EOFError, KeyboardInterrupt):
            print()
            raise JkeyError("Export cancelled.")
        if pw != session_pw:
            raise JkeyError("Incorrect password. Export cancelled.")

    t = args.type
    output = args.output

    if t == "totp":
        _export_totp(output)
    elif t == "passwords":
        _export_passwords(output)
    elif t == "recovery":
        _export_recovery(output)
    elif t == "qr":
        if not output:
            raise JkeyError("-o <directory> required for QR export.")
        _export_qr(output)
    elif t == "all":
        if not output:
            raise JkeyError("-o <directory> required for full export.")
        os.makedirs(output, mode=0o700, exist_ok=True)

        totp_data = load_totp()
        if totp_data:
            p = os.path.join(output, "totp.json")
            write_secure_text(p, _build_totp_content(totp_data), atomic=True)
            print(f"  {p}")

        pw_data = load_passwords()
        if pw_data:
            p = os.path.join(output, "passwords.csv")
            write_secure_text(p, _build_passwords_content(pw_data), newline="", atomic=True)
            print(f"  {p}")

        rc_data = load_recovery()
        if rc_data:
            p = os.path.join(output, "recovery.txt")
            write_secure_text(p, _build_recovery_content(rc_data) + "\n", atomic=True)
            print(f"  {p}")

        qr_dir = os.path.join(output, "qr")
        names = list_qr_images()
        if names:
            os.makedirs(qr_dir, mode=0o700, exist_ok=True)
            for name in names:
                img = load_qr_image(name)
                if img:
                    p = os.path.join(qr_dir, f"{name}.jpg")
                    write_secure_bytes(p, img, atomic=True)
            print(f"  {qr_dir}/ ({len(names)} images)")

        print(f"Exported to {output}")
