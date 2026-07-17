import getpass

from jkey.pm.core import load_passwords, save_passwords


def edit_password(name: str):
    data = load_passwords()
    if data is None:
        return
    if name not in data:
        print(f"Error: Password '{name}' not found.")
        return
    try:
        pw = getpass.getpass(f"New password for '{name}': ")
    except (EOFError, KeyboardInterrupt):
        print()
        return
    if not pw:
        print("Password cannot be empty.")
        return
    try:
        pw2 = getpass.getpass(f"Confirm new password for '{name}': ")
    except (EOFError, KeyboardInterrupt):
        print()
        return
    if pw != pw2:
        print("Passwords do not match.")
        return
    data[name] = pw
    save_passwords(data)
    print(f"Password updated: {name}")
