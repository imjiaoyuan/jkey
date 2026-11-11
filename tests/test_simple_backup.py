"""The short command interface and manual conflict resolution workflow."""

import json
import os
import shutil
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from jkey import aes, cli
from jkey.errors import JkeyError
from jkey.pv import core, transaction
from jkey.pv.backup import core as backup
from jkey.pv.backup.remotes import open_remote
from jkey.pv.backup.remotes.rclone import RcloneRemote


@pytest.mark.parametrize("argv,action,name", [
    (["backup", "s3"], "run", "s3"),
    (["restore", "s3"], "restore", "s3"),
    (["backup", "rclone:r2"], "run", "rclone:r2"),
    (["restore", "rclone:r2:bucket/jkey"], "restore", "rclone:r2:bucket/jkey"),
    (["backup", "run"], "run", "run"),
    (["backup", "add"], "run", "add"),
])
def test_short_commands_have_no_reserved_backend_names(argv, action, name):
    args = cli._build_parser().parse_args(argv)
    assert args.action == action
    assert args.name == name


def test_main_short_command_dispatch(vault_dir, monkeypatch):
    called = []
    monkeypatch.setattr(backup, "cmd_backup", lambda args: called.append((args.action, getattr(args, "name", None))))
    for argv in (["backup", "cloud"], ["restore", "cloud"], ["remote", "ls"]):
        monkeypatch.setattr("sys.argv", ["jkey", *argv])
        cli.main()
    assert called == [("run", "cloud"), ("restore", "cloud"), ("ls", None)]


def test_repeated_conflicts_keep_every_old_version(tmp_path):
    path = tmp_path / "passwords.jkey"
    path.write_bytes(b"first")
    first_backup = transaction.preserve_and_write(path, b"second")
    second_backup = transaction.preserve_and_write(path, b"third")
    assert first_backup.name == "passwords.jkey.bak"
    assert second_backup != first_backup and second_backup.name.endswith(".bak")
    assert first_backup.read_bytes() == b"first"
    assert second_backup.read_bytes() == b"second"
    assert path.read_bytes() == b"third"
    assert transaction.preserve_and_write(path, b"third") is None
    assert len(list(tmp_path.glob("*.bak"))) == 2


def test_identical_restore_makes_no_backup(vault_dir, tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    (source / "totp.jkey").write_bytes(b"same")
    (vault_dir / "totp.jkey").write_bytes(b"same")
    backup._write_into_vault(str(source), ["totp.jkey"])
    assert not list(vault_dir.rglob("*.bak"))


def test_bak_can_be_decrypted_and_merged_without_unlocking_current_vault(vault_dir, tmp_path, monkeypatch):
    from jkey.pv.decrypt import decrypt_file
    from jkey.pv.encrypt import encrypt_file

    core.ensure_dir()
    core.write_jkey(core.TOTP_FILE, aes.encrypt({"new": "data"}, "new-password"))
    old = Path(core.PASSWORDS_FILE + ".bak")
    old.write_text(json.dumps(aes.encrypt({"old-site": "old-value"}, "old-password")))
    monkeypatch.setattr(core, "prompt_password", lambda *_: "old-password")
    decrypted = tmp_path / "merged.json"
    decrypt_file(str(old), str(decrypted))
    assert json.loads(decrypted.read_text()) == {"old-site": "old-value"}
    assert not core.is_unlocked()
    # Re-encryption produces the native dictionary, rather than wrapping JSON as a binary file.
    decrypted.write_text(json.dumps({"old-site": "old-value", "new-site": "new-value"}))
    monkeypatch.setattr(core, "prompt_password", lambda *_: "new-password")
    output = Path(core.PASSWORDS_FILE)
    encrypt_file(str(decrypted), str(output), json_data=True)
    assert aes.decrypt(json.loads(output.read_text()), "new-password") == {
        "old-site": "old-value", "new-site": "new-value"}
    assert old.exists()
    assert core.unlock_all("new-password")
    assert core.load_passwords() == {"old-site": "old-value", "new-site": "new-value"}


@pytest.mark.parametrize("url,root", [
    ("rclone:r2", "r2:"),
    ("rclone:r2:bucket/jkey", "r2:bucket/jkey"),
    ("rclone:r2/bucket/jkey", "r2:bucket/jkey"),
])
def test_rclone_target_mapping(url, root):
    remote = open_remote({"url": url})
    assert isinstance(remote, RcloneRemote)
    assert remote.root == root


def test_missing_rclone_has_actionable_error(monkeypatch):
    def missing(*a, **kw):
        raise FileNotFoundError

    monkeypatch.setattr(subprocess, "run", missing)
    with pytest.raises(JkeyError, match="rclone is not installed"):
        RcloneRemote("rclone:r2").list_keys()


def test_rclone_failure_does_not_expose_provider_credentials(monkeypatch):
    monkeypatch.setattr(subprocess, "run", lambda *a, **kw: SimpleNamespace(
        returncode=1, stdout="", stderr="secret_key=do-not-print"))
    with pytest.raises(JkeyError) as exc:
        RcloneRemote("rclone:r2").list_keys()
    assert "do-not-print" not in str(exc.value)


@pytest.mark.skipif(shutil.which("rclone") is None, reason="rclone not installed")
def test_real_rclone_backup_restore_using_isolated_config(vault_dir, tmp_path, monkeypatch):
    # Exercise the installed rclone binary with an alias to a temporary local directory.
    # No real user config, credentials or cloud storage are read or written.
    config = tmp_path / "rclone.conf"
    storage = tmp_path / "storage"
    config.write_text(f"[r2]\ntype = alias\nremote = {storage}\n")
    for key in list(os.environ):
        if key.startswith("RCLONE_"):
            monkeypatch.delenv(key)
    monkeypatch.setenv("RCLONE_CONFIG", str(config))
    core.ensure_dir()
    (vault_dir / "totp.jkey").write_bytes(b"encrypted generation one")
    monkeypatch.setattr("sys.argv", ["jkey", "backup", "rclone:r2"])
    cli.main()
    assert list(storage.glob("*.tar.gz"))
    RcloneRemote("rclone:r2").probe()
    (vault_dir / "totp.jkey").write_bytes(b"encrypted generation two")
    monkeypatch.setattr("builtins.input", lambda *_: "y")
    monkeypatch.setattr("sys.argv", ["jkey", "restore", "rclone:r2"])
    cli.main()
    assert (vault_dir / "totp.jkey").read_bytes() == b"encrypted generation one"
    assert (vault_dir / "totp.jkey.bak").read_bytes() == b"encrypted generation two"
    assert not core.is_unlocked()
    # An explicit alias in jkey can reuse that same rclone target.
    backup.save_remotes({"cloud": {"url": "rclone:r2"}})
    monkeypatch.setattr("sys.argv", ["jkey", "backup", "cloud"])
    cli.main()
    assert len(list(storage.glob("*.tar.gz"))) == 2
