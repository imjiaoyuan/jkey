from jkey.pv.core import (
    delete_qr_image,
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

    delete_qr_image(account)

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
