from jkey.pv.core import is_unlocked, lock


def cmd_lock():
    if not is_unlocked():
        print("Vault is already locked.")
        return
    lock()
    print("Vault locked.")
