import os

from jkey.errors import JkeyError
from jkey.pv.core import load_recovery, save_recovery


def rc_add_file(file_path: str):
    if not os.path.exists(file_path):
        raise JkeyError(f"File not found: {file_path}")
    base = os.path.basename(file_path)
    name = os.path.splitext(base)[0]
    if not name:
        raise JkeyError(f"Could not determine account name from {file_path}")
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            codes = [line.strip() for line in f if line.strip()]
    except OSError as e:
        raise JkeyError(f"Cannot read file '{file_path}': {e}") from e
    if not codes:
        raise JkeyError(f"No recovery codes found in {file_path}")
    data = load_recovery()
    if name in data:
        try:
            response = input(f"'{name}' already exists. Overwrite? (y/N): ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print()
            raise JkeyError("Import cancelled.")
        if response != "y":
            raise JkeyError("Import cancelled.")
    data[name] = codes
    save_recovery(data)
    print(f"Imported {len(codes)} recovery codes for {name}")
