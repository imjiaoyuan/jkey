from jkey.pv.core import has_session, is_unlocked, lock


def cmd_lock():
    if not is_unlocked() and not has_session():
        print("Vault is already locked.")
        return
    lock()
    print("Vault locked.")
