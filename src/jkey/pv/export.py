import csv
import getpass
import io
import json
import os

from jkey.pv.core import (
    _ensure_unlocked,
    _password_from_env,
    list_qr_images,
    load_passwords,
    load_qr_image,
    load_recovery,
    load_totp,
    verify_password,
)


def cmd_export(args):
    if not _ensure_unlocked():
        return

    env_pw = _password_from_env()
    if env_pw and verify_password(env_pw):
        pass
    else:
        pw = getpass.getpass("Confirm master password to export: ")
        if not verify_password(pw):
            print("Incorrect password. Export cancelled.")
            return

    t = args.type
    output = args.output

    if t == "totp":
        data = load_totp()
        if data is None:
            return
        out = json.dumps(data, indent=4, ensure_ascii=False) + "\n"
        if output:
            with open(output, "w", encoding="utf-8") as f:
                f.write(out)
            print(f"Exported TOTP secrets to {output}")
        else:
            print(out, end="")

    elif t == "passwords":
        data = load_passwords()
        if data is None:
            return
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(["name", "password"])
        for name, pw_val in sorted(data.items()):
            w.writerow([name, pw_val])
        out = buf.getvalue()
        if output:
            with open(output, "w", encoding="utf-8", newline="") as f:
                f.write(out)
            print(f"Exported passwords to {output}")
        else:
            print(out, end="")

    elif t == "recovery":
        data = load_recovery()
        if data is None:
            return
        lines = []
        for account in sorted(data.keys()):
            lines.append(f"Account: {account}")
            for code in data[account]:
                lines.append(f"  {code}")
            lines.append("")
        out = "\n".join(lines)
        if output:
            with open(output, "w", encoding="utf-8") as f:
                f.write(out)
                f.write("\n")
            print(f"Exported recovery codes to {output}")
        else:
            print(out)

    elif t == "qr":
        if not output:
            print("Error: -o <directory> required for QR export.")
            return
        os.makedirs(output, exist_ok=True)
        names = list_qr_images()
        if not names:
            print("No QR images found.")
            return
        for name in names:
            img = load_qr_image(name)
            if img:
                path = os.path.join(output, f"{name}.jpg")
                with open(path, "wb") as f:
                    f.write(img)
        print(f"Exported {len(names)} QR images to {output}")

    elif t == "all":
        if not output:
            print("Error: -o <directory> required for full export.")
            return
        os.makedirs(output, exist_ok=True)

        totp_data = load_totp()
        if totp_data:
            p = os.path.join(output, "totp.json")
            with open(p, "w", encoding="utf-8") as f:
                json.dump(totp_data, f, indent=4, ensure_ascii=False)
                f.write("\n")
            print(f"  {p}")

        pw_data = load_passwords()
        if pw_data:
            p = os.path.join(output, "passwords.csv")
            with open(p, "w", encoding="utf-8", newline="") as f:
                w = csv.writer(f)
                w.writerow(["name", "password"])
                for name, pw_val in sorted(pw_data.items()):
                    w.writerow([name, pw_val])
            print(f"  {p}")

        rc_data = load_recovery()
        if rc_data:
            p = os.path.join(output, "recovery.txt")
            with open(p, "w", encoding="utf-8") as f:
                for account in sorted(rc_data.keys()):
                    f.write(f"Account: {account}\n")
                    for code in rc_data[account]:
                        f.write(f"  {code}\n")
                    f.write("\n")
            print(f"  {p}")

        qr_dir = os.path.join(output, "qr")
        names = list_qr_images()
        if names:
            os.makedirs(qr_dir, exist_ok=True)
            for name in names:
                img = load_qr_image(name)
                if img:
                    p = os.path.join(qr_dir, f"{name}.jpg")
                    with open(p, "wb") as f:
                        f.write(img)
            print(f"  {qr_dir}/ ({len(names)} images)")

        print(f"Exported to {output}")
