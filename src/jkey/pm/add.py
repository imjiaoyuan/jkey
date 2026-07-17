import getpass

from jkey.pm.core import load_passwords, save_passwords


def add_password(name: str):
    data = load_passwords()
    if data is None:
        return

    if name in data:
        while True:
            try:
                choice = (
                    input(f"'{name}' already exists. (o)verwrite / (a)dd suffix / (c)ancel? (o/a/c): ").strip().lower()
                )
            except (EOFError, KeyboardInterrupt):
                print()
                return
            if choice == "c":
                return
            elif choice == "a":
                try:
                    suffix = input("Suffix: ").strip()
                except (EOFError, KeyboardInterrupt):
                    print()
                    return
                if not suffix:
                    print("Suffix cannot be empty.")
                    continue
                name = f"{name}-{suffix}"
                break
            elif choice == "o":
                break
            else:
                print("Invalid choice. Please enter 'o', 'a', or 'c'.")

    try:
        pw = getpass.getpass(f"Password for '{name}': ")
    except (EOFError, KeyboardInterrupt):
        print()
        return
    if not pw:
        print("Password cannot be empty.")
        return
    try:
        pw2 = getpass.getpass(f"Confirm password for '{name}': ")
    except (EOFError, KeyboardInterrupt):
        print()
        return
    if pw != pw2:
        print("Passwords do not match.")
        return
    data[name] = pw
    save_passwords(data)
    print(f"Password stored: {name}")
