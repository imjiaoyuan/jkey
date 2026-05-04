import getpass

from jkey.pm.core import load_passwords, save_passwords


def add_password(name: str):
    data = load_passwords()
    if data is None:
        return
    pw = getpass.getpass(f"Password for '{name}': ")
    if not pw:
        print("Password cannot be empty.")
        return
    data[name] = pw
    save_passwords(data)
    print(f"Password stored: {name}")
