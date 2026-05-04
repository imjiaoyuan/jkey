import os

from jkey.pv.core import load_recovery, save_recovery


def rc_add_file(file_path: str):
    if not os.path.exists(file_path):
        print(f"Error: File not found: {file_path}")
        return
    base = os.path.basename(file_path)
    name = os.path.splitext(base)[0]
    if not name:
        print(f"Error: Could not determine account name from {file_path}")
        return
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            codes = [line.strip() for line in f if line.strip()]
    except OSError as e:
        print(f"Error: Cannot read file '{file_path}': {e}")
        return
    if not codes:
        print(f"Error: No recovery codes found in {file_path}")
        return
    data = load_recovery()
    if data is None:
        return
    data[name] = codes
    save_recovery(data)
    print(f"Imported {len(codes)} recovery codes for {name}")
