from jkey.errors import JkeyError
from jkey.pv.core import delete_qr_image, load_recovery, load_totp, save_totp
from jkey.rc.rm import remove_recovery


def remove_account(account: str):
    data = load_totp()
    if account not in data:
        raise JkeyError(f"Account '{account}' not found.")
    del data[account]
    save_totp(data)

    delete_qr_image(account)

    rc = load_recovery()
    if rc and account in rc:
        try:
            response = input(f"Also delete recovery codes for '{account}'? (y/N): ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print()
            response = "n"
        if response == "y":
            remove_recovery(account)
        else:
            print("Recovery codes kept.")

    print(f"Removed 2FA account: {account}")
