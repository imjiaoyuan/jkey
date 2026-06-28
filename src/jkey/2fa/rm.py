import os

from jkey.pv.core import (
    _qr_path,
    load_recovery,
    load_totp,
    save_recovery,
    save_totp,
)


def remove_account(account: str):
    data = load_totp()
    if data is None:
        return
    if account not in data:
        print(f"Error: Account '{account}' not found.")
        return
    del data[account]
    save_totp(data)

    qr_path = _qr_path(account)
    if os.path.exists(qr_path):
        try:
            os.unlink(qr_path)
        except OSError:
            pass

    rc = load_recovery()
    if rc and account in rc:
        try:
            response = input(f"Also delete recovery codes for '{account}'? (y/N): ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print()
            response = "n"
        if response == "y":
            del rc[account]
            save_recovery(rc)
        else:
            print("Recovery codes kept.")

    print(f"Removed 2FA account: {account}")
