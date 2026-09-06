import binascii

from jkey.pv.core import filter_keys, load_totp

from .core import totp


def list_accounts(keyword: str | None = None) -> list[tuple[str, str]]:
    data = load_totp()
    result = []
    for acc_id in filter_keys(data, keyword):
        secret = data[acc_id]
        try:
            result.append((acc_id, totp(secret)))
        except binascii.Error as e:
            result.append((acc_id, f"Error: {e}"))
    return result
