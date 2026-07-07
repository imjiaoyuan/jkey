import os

from jkey.pv.core import (
    CONFIG_DIR,
    PASSWORDS_FILE,
    RECOVERY_FILE,
    TOTP_FILE,
    is_unlocked,
)


def cmd_status():
    vault_exists = any(os.path.exists(p) for p in (TOTP_FILE, PASSWORDS_FILE, RECOVERY_FILE))
    unlocked = is_unlocked()

    print(f"Config directory: {CONFIG_DIR}")
    print(f"Vault initialized: {'yes' if vault_exists else 'no'}")
    print(f"Vault unlocked: {'yes' if unlocked else 'no'}")
