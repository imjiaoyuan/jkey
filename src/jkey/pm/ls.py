from jkey.pm.core import load_passwords


def list_passwords(keyword: str | None = None):
    data = load_passwords()
    if data is None:
        return
    if not data:
        print("No stored passwords found.")
        return
    keys = sorted(data.keys())
    if keyword:
        keys = [k for k in keys if keyword.lower() in k.lower()]
        if not keys:
            print(f"No passwords matching '{keyword}'.")
            return
    for name in keys:
        print(f"{name}: {data[name]}")
