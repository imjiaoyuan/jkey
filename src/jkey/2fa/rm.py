from jkey.pv.core import load_recovery, load_totp, save_recovery, save_totp


def remove_account(account: str):
    data = load_totp()
    if data is None:
        return
    if account not in data:
        print(f"Error: Account '{account}' not found.")
        return
    del data[account]
    save_totp(data)

    rc = load_recovery()
    if rc and account in rc:
        del rc[account]
        save_recovery(rc)

    print(f"Removed 2FA account: {account}")
