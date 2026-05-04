import os

from jkey.pv.core import (
    _encrypt_file,
    _ensure_dir,
    _password_from_env,
    _prompt_password,
    _unlock_all,
)


def cmd_init():
    from jkey.pv.core import CONFIG_DIR, PASSWORDS_FILE, RECOVERY_FILE, TOTP_FILE

    if os.path.exists(TOTP_FILE):
        print("Vault already exists. Use 'jkey pv set-pw' to change password.")
        return
    pw1 = _password_from_env()
    if pw1 is None:
        pw1 = _prompt_password("Set master password: ")
        if not pw1:
            print("Password cannot be empty.")
            return
        pw2 = _prompt_password("Confirm master password: ")
        if pw1 != pw2:
            print("Passwords do not match.")
            return

    _ensure_dir()
    _encrypt_file(TOTP_FILE, {}, pw1)
    _encrypt_file(PASSWORDS_FILE, {}, pw1)
    _encrypt_file(RECOVERY_FILE, {}, pw1)
    _unlock_all(pw1)
    print(f"Vault initialized at {CONFIG_DIR}")
