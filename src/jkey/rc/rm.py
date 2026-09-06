from jkey.errors import JkeyError
from jkey.pv.core import load_recovery, save_recovery


def remove_recovery(account: str) -> bool:
    """Remove one account's recovery codes. Returns False if the account does not exist."""
    data = load_recovery()
    if account not in data:
        return False
    del data[account]
    save_recovery(data)
    print(f"Removed recovery codes for {account}")
    return True


def rc_remove(account: str):
    if not remove_recovery(account):
        raise JkeyError(f"Recovery codes for '{account}' not found.")
