from jkey.errors import JkeyError
from jkey.pv.core import load_passwords, save_passwords


def delete_password(name: str):
    data = load_passwords()
    if name not in data:
        raise JkeyError(f"Password '{name}' not found.")
    del data[name]
    save_passwords(data)
    print(f"Password deleted: {name}")
