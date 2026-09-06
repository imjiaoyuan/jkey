from jkey.errors import JkeyError
from jkey.pv.core import (
    change_master_password,
    confirm_weak_password,
    ensure_unlocked,
    prompt_password,
    vault_exists,
)


def cmd_set_pw():
    if not vault_exists():
        raise JkeyError("Vault not initialized. Run 'jkey pv init' first.")
    ensure_unlocked()
    pw = prompt_password("New master password: ")
    if not pw:
        raise JkeyError("Password cannot be empty.")
    if not confirm_weak_password(pw):
        raise JkeyError("Password change cancelled.")
    pw2 = prompt_password("Confirm new master password: ")
    if pw != pw2:
        raise JkeyError("Passwords do not match.")
    if not change_master_password(pw):
        raise JkeyError("Failed to change master password.")
    print("Master password changed.")
