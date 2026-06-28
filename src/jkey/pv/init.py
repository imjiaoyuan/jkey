import os

from jkey.pv.core import (
    _check_password_strength,
    _encrypt_file,
    _ensure_dir,
    _password_from_env,
    _prompt_password,
    _unlock_all,
)


def cmd_init():
    from jkey.pv.core import CONFIG_DIR, PASSWORDS_FILE, RECOVERY_FILE, TOTP_FILE

    if any(os.path.exists(p) for p in (TOTP_FILE, PASSWORDS_FILE, RECOVERY_FILE)):
        print("Vault already exists. Use 'jkey pv set-pw' to change password.")
        return
    pw1 = _password_from_env()
    if pw1 is None:
        pw1 = _prompt_password("Set master password: ")
        if not pw1:
            print("Password cannot be empty.")
            return

        is_strong, warning = _check_password_strength(pw1)
        if not is_strong:
            print(f"Warning: {warning}")
            try:
                response = input("Continue anyway? (y/N): ").strip().lower()
                if response != "y":
                    print("Vault initialization cancelled.")
                    return
            except (EOFError, KeyboardInterrupt):
                print("\nVault initialization cancelled.")
                return

        pw2 = _prompt_password("Confirm master password: ")
        if pw1 != pw2:
            print("Passwords do not match.")
            return

    _ensure_dir()
    for path in (TOTP_FILE, PASSWORDS_FILE, RECOVERY_FILE):
        if not os.path.exists(path):
            _encrypt_file(path, {}, pw1)
    _unlock_all(pw1)
    print(f"Vault initialized at {CONFIG_DIR}")
