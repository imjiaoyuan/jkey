from jkey.errors import JkeyError
from jkey.pv.core import load_passwords, prompt_password_confirmed, save_passwords


def edit_password(name: str):
    data = load_passwords()
    if name not in data:
        raise JkeyError(f"Password '{name}' not found.")
    pw = prompt_password_confirmed(f"New password for '{name}': ", f"Confirm new password for '{name}': ")
    data[name] = pw
    save_passwords(data)
    print(f"Password updated: {name}")
