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
    core._encrypt_file(core.TOTP_FILE, core._totp_cache, pw1)
    core._encrypt_file(core.PASSWORDS_FILE, core._passwords_cache, pw1)
    core._encrypt_file(core.RECOVERY_FILE, core._recovery_cache, pw1)
    core._session_password = pw1
    core._save_session(pw1, core._totp_cache, core._passwords_cache, core._recovery_cache)
    print("Master password changed.")
