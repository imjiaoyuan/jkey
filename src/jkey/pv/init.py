import os

from jkey.pv.core import (
    _encrypt_file,
    _ensure_dir,
    _password_from_env,
    _prompt_password,
    _unlock_all,
)


def _check_password_strength(password: str) -> tuple[bool, str]:
    """Check password strength and return (is_strong, warning_message)."""
    if len(password) < 8:
        return False, "Password is too short (minimum 8 characters recommended)."

    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_special = any(not c.isalnum() for c in password)

    strength_count = sum([has_upper, has_lower, has_digit, has_special])

    if len(password) < 12:
        return False, "Password should be at least 12 characters for better security."

    if strength_count < 3:
        return False, "Password should include uppercase, lowercase, digits, and special characters."

    return True, ""


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
    _encrypt_file(TOTP_FILE, {}, pw1)
    _encrypt_file(PASSWORDS_FILE, {}, pw1)
    _encrypt_file(RECOVERY_FILE, {}, pw1)
    _unlock_all(pw1)
    print(f"Vault initialized at {CONFIG_DIR}")
