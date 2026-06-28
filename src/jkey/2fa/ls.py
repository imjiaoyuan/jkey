import binascii

from jkey.pv.core import load_totp

from .core import totp


def list_accounts(keyword: str | None = None) -> list[tuple[str, str]] | None:
    data = load_totp()
    if data is None:
        return None
    if not data:
        return []
    keys = sorted(data.keys())
    if keyword:
        keys = [k for k in keys if keyword.lower() in k.lower()]
        if not keys:
            return []
    result = []
    for acc_id in keys:
        secret = data[acc_id]
        try:
            result.append((acc_id, totp(secret)))
        except binascii.Error as e:
            result.append((acc_id, f"Error: {e}"))
    return result
