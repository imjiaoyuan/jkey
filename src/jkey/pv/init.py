import os

from jkey.errors import JkeyError
from jkey.pv import core


def cmd_init():
    if core.vault_exists():
        raise JkeyError("Vault already exists. Use 'jkey pv set-pw' to change password.")
    pw = core.password_from_env()
    if not pw:
        pw = core.prompt_password("Set master password: ")
        if not pw:
            raise JkeyError("Password cannot be empty.")
        if not core.confirm_weak_password(pw):
            raise JkeyError("Vault initialization cancelled.")
        pw2 = core.prompt_password("Confirm master password: ")
        if pw != pw2:
            raise JkeyError("Passwords do not match.")

    core.ensure_dir()
    for path in (core.TOTP_FILE, core.PASSWORDS_FILE, core.RECOVERY_FILE):
        if not os.path.exists(path):
            core.encrypt_file(path, {}, pw)
    core.set_unlocked(pw, {}, {}, {})
    print(f"Vault initialized at {core.CONFIG_DIR}")
