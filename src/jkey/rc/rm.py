from jkey.pv.core import load_recovery, save_recovery


def rc_remove(account: str):
    data = load_recovery()
    if data is None:
        return
    if account not in data:
        print(f"Error: Recovery codes for '{account}' not found.")
        return
    del data[account]
    save_recovery(data)
    print(f"Removed recovery codes for {account}")
