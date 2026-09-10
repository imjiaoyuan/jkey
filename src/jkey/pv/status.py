from jkey.pv import core


def cmd_status():
    print(f"Config directory: {core.CONFIG_DIR}")
    print(f"Vault initialized: {'yes' if core.vault_exists() else 'no'}")
    unlocked = core.is_unlocked() or core.has_session()
    print(f"Vault unlocked: {'yes' if unlocked else 'no'}")
