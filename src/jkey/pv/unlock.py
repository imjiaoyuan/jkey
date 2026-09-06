from jkey.errors import JkeyError
from jkey.pv.core import ensure_unlocked, is_unlocked, vault_exists


def cmd_unlock():
    if is_unlocked():
        print("Vault is already unlocked.")
        return
    if not vault_exists():
        raise JkeyError("Vault not initialized. Run 'jkey pv init' first.")
    ensure_unlocked()
    print("Vault unlocked.")
