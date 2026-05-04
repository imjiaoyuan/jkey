import os

from jkey.pv.core import TOTP_FILE, _ensure_unlocked, is_unlocked


def cmd_unlock():
    if is_unlocked():
        print("Vault is already unlocked.")
        return
    if not os.path.exists(TOTP_FILE):
        print("Error: Vault not initialized. Run 'jkey pv init' first.")
        return
    if _ensure_unlocked():
        print("Vault unlocked.")
