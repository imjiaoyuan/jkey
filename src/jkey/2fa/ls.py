import binascii

from jkey.pv.core import load_totp

from .core import totp


def list_accounts(keyword: str | None = None):
    data = load_totp()
    if data is None:
        return
    if not data:
        print("No 2FA accounts found.")
        return
    keys = sorted(data.keys())
    if keyword:
        keys = [k for k in keys if keyword.lower() in k.lower()]
        if not keys:
            print(f"No accounts matching '{keyword}'.")
            return
    for acc_id in keys:
        secret = data[acc_id]
        try:
            print(f"{acc_id}: {totp(secret)}")
        except binascii.Error as e:
            print(f"Error processing '{acc_id}': {e}")
