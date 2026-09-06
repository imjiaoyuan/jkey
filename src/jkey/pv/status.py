from jkey.pv import core


def cmd_status():
    print(f"Config directory: {core.CONFIG_DIR}")
    print(f"Vault initialized: {'yes' if core.vault_exists() else 'no'}")
    print(f"Vault unlocked: {'yes' if core.is_unlocked() else 'no'}")
