from jkey.errors import JkeyError
from jkey.pv.core import ensure_unlocked, has_session, is_unlocked, vault_exists


def cmd_unlock():
    if is_unlocked() or has_session():
        print("Vault is already unlocked.")
        return
    if not vault_exists():
        raise JkeyError("Vault not initialized. Run 'jkey pv init' first.")
    ensure_unlocked()
    print("Vault unlocked.")
