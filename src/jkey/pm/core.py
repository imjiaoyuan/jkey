import csv
import getpass

from jkey.pv.core import load_passwords, save_passwords


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


def show_password(name: str):
    data = load_passwords()
    if data is None:
        return
    if name not in data:
        print(f"Error: Password '{name}' not found.")
        return
    print(f"{name}: {data[name]}")


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


def import_from_csv(csv_path: str):
    data = load_passwords()
    if data is None:
        return
    try:
        with open(csv_path, "r", encoding="utf-8") as f:
            reader = csv.reader(f)
            rows = list(reader)
    except OSError as e:
        print(f"Error: Cannot read file '{csv_path}': {e}")
        return
    if not rows:
        print("Error: Empty CSV file.")
        return
    first = rows[0]
    if len(first) >= 2 and first[0].strip().lower() in ("name", "url", "account", "key"):
        rows = rows[1:]
    imported = 0
    for row in rows:
        if len(row) < 2:
            continue
        name = row[0].strip()
        pw = row[1].strip()
        if name and pw:
            data[name] = pw
            imported += 1
    save_passwords(data)
    print(f"Imported {imported} passwords from {csv_path}")
