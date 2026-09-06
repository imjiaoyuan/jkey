from jkey.errors import JkeyError
from jkey.pv.core import load_passwords, prompt_password_confirmed, save_passwords


def add_password(name: str):
    data = load_passwords()

    if name in data:
        while True:
            try:
                choice = (
                    input(f"'{name}' already exists. (o)verwrite / (a)dd suffix / (c)ancel? (o/a/c): ").strip().lower()
                )
            except (EOFError, KeyboardInterrupt):
                print()
                raise JkeyError("Cancelled.")
            if choice == "c":
                raise JkeyError("Cancelled.")
            elif choice == "a":
                while True:
                    try:
                        suffix = input("Suffix: ").strip()
                    except (EOFError, KeyboardInterrupt):
                        print()
                        raise JkeyError("Cancelled.")
                    if not suffix:
                        print("Suffix cannot be empty.")
                        continue
                    candidate = f"{name}-{suffix}"
                    if candidate in data:
                        print(f"'{candidate}' already exists.")
                        continue
                    name = candidate
                    break
                break
            elif choice == "o":
                break
            else:
                print("Invalid choice. Please enter 'o', 'a', or 'c'.")

    pw = prompt_password_confirmed(f"Password for '{name}': ", f"Confirm password for '{name}': ")
    data[name] = pw
    save_passwords(data)
    print(f"Password stored: {name}")
