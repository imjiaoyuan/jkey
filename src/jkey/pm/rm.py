from jkey.pm.core import load_passwords, save_passwords


def delete_password(name: str):
    data = load_passwords()
    if data is None:
        return
    if name not in data:
        print(f"Error: Password '{name}' not found.")
        return
    del data[name]
    save_passwords(data)
    print(f"Password deleted: {name}")
