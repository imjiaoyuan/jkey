import os

import jkey.pv.core as core


def cmd_set_pw():
    if not os.path.exists(core.TOTP_FILE):
        print("Error: Vault not initialized. Run 'jkey pv init' first.")
        return
    if not core._ensure_unlocked():
        return
    pw1 = core._prompt_password("New master password: ")
    if not pw1:
        print("Password cannot be empty.")
        return
    pw2 = core._prompt_password("Confirm new master password: ")
    if pw1 != pw2:
        print("Passwords do not match.")
        return
    if core.change_master_password(pw1):
        print("Master password changed.")
