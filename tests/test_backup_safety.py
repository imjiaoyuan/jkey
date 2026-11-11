"""Failure regressions for recovery points, remote publication and exact restore."""

import contextlib
import io
import json
import os
import subprocess
import sys
import tarfile
from pathlib import Path
from types import SimpleNamespace

import pytest

from jkey.errors import JkeyError
from jkey.pv import core, transaction
from jkey.pv.backup import core as backup
from jkey.pv.backup.remotes.local import LocalRemote
from jkey.pv.backup.remotes.s3 import S3Remote


def args(**kw):
    return SimpleNamespace(**dict({"name": "nas", "keep": None, "date": None,
                                   "output": None, "into_vault": False}, **kw))


@pytest.fixture
def configured(vault_dir, tmp_path):
    core.ensure_dir()
    for name in backup._VAULT_FILES:
        (vault_dir / name).write_text('{"generation": "old"}')
    remote = tmp_path / "remote"
    backup.save_remotes({"nas": {"url": str(remote)}})
    return vault_dir, remote


def snapshot(remote):
    return next(remote.glob("*.tar.gz"))


def test_same_second_runs_preserve_distinct_snapshots(configured, monkeypatch):
    _, remote = configured
    monkeypatch.setattr(backup.time, "strftime", lambda *_: "20261111-140000")
    backup._cmd_run(args())
    backup._cmd_run(args())
    assert len(list(remote.glob("*.tar.gz"))) == 2
    backup._cmd_verify(args())


def test_probe_never_touches_existing_manifest(configured, monkeypatch):
    _, remote = configured
    backup._cmd_run(args())
    before = {p.name: p.read_bytes() for p in remote.iterdir()}
    LocalRemote(str(remote)).probe()
    assert {p.name: p.read_bytes() for p in remote.iterdir()} == before


def test_local_publish_cannot_overwrite_snapshot(tmp_path):
    remote = LocalRemote(str(tmp_path / "remote"))
    source = tmp_path / "data"
    source.write_bytes(b"first")
    remote.put(str(source), "20261111-140000.tar.gz")
    source.write_bytes(b"second")
    with pytest.raises(JkeyError):
        remote.put(str(source), "20261111-140000.tar.gz")
    assert (tmp_path / "remote/20261111-140000.tar.gz").read_bytes() == b"first"


def test_restore_requires_manifest(configured, tmp_path):
    _, remote = configured
    backup._cmd_run(args())
    snap = snapshot(remote)
    remote.joinpath(snap.name.removesuffix(".tar.gz") + ".sha256").unlink()
    with pytest.raises(JkeyError, match="not found"):
        backup._cmd_restore(args(date=snap.name.removesuffix(".tar.gz"), output=str(tmp_path / "out")))
    assert not (tmp_path / "out").exists()


def test_restore_rejects_manifest_read_failure(configured, tmp_path, monkeypatch):
    _, _remote = configured
    backup._cmd_run(args())
    original = LocalRemote.get

    def fail(self, key, dest, progress=None):
        if key.endswith(".sha256"):
            raise JkeyError("access denied")
        original(self, key, dest, progress)

    monkeypatch.setattr(LocalRemote, "get", fail)
    with pytest.raises(JkeyError, match="access denied"):
        backup._cmd_restore(args(output=str(tmp_path / "out")))
    assert not (tmp_path / "out").exists()


def test_restore_keeps_conflicting_output_as_bak(configured, tmp_path):
    backup._cmd_run(args())
    out = tmp_path / "out"
    out.mkdir()
    (out / "passwords.jkey").write_bytes(b"pre-existing")
    backup._cmd_restore(args(output=str(out)))
    assert (out / "passwords.jkey.bak").read_bytes() == b"pre-existing"
    assert json.loads((out / "passwords.jkey").read_text()) == {"generation": "old"}


def test_restore_preserves_local_only_data(configured, tmp_path, monkeypatch):
    vault, _ = configured
    (vault / "passwords.jkey").unlink()
    (vault / "recovery.jkey").unlink()
    backup._cmd_run(args())
    (vault / "passwords.jkey").write_bytes(b"later passwords")
    (vault / "qr/later.jkey").write_bytes(b"later QR")
    monkeypatch.setattr("builtins.input", lambda *_: "y")
    backup._cmd_restore(args(into_vault=True))
    assert (vault / "passwords.jkey").read_bytes() == b"later passwords"
    assert (vault / "qr/later.jkey").read_bytes() == b"later QR"
    assert not (vault / "restore-backups").exists()


def test_failed_file_replace_leaves_old_file_and_backup(configured, tmp_path, monkeypatch):
    vault, _ = configured
    out = tmp_path / "out"
    out.mkdir()
    for name in backup._VAULT_FILES:
        (out / name).write_bytes(b"new")
    original = os.replace

    def fail(src, dst):
        if str(dst).endswith("passwords.jkey"):
            raise OSError("injected commit failure")
        return original(src, dst)

    monkeypatch.setattr(os, "replace", fail)
    with pytest.raises(JkeyError, match="failed to restore"):
        backup._write_into_vault(str(out), list(backup._VAULT_FILES))
    assert (vault / "totp.jkey").read_bytes() == b"new"
    assert json.loads((vault / "totp.jkey.bak").read_text()) == {"generation": "old"}
    assert json.loads((vault / "passwords.jkey").read_text()) == {"generation": "old"}
    assert json.loads((vault / "passwords.jkey.bak").read_text()) == {"generation": "old"}
    assert not core.is_unlocked()


def test_process_death_is_recovered_on_next_vault_read(configured):
    vault, _ = configured
    script = '''
import os, sys
from jkey.pv import transaction
original = os.replace
def die(src, dst):
    if str(src).endswith('new-1'):
        os._exit(91)
    return original(src, dst)
os.replace = die
transaction.replace(sys.argv[1], {'totp.jkey': b'{"new":true}', 'passwords.jkey': b'{"new":true}'})
'''
    result = subprocess.run([sys.executable, "-c", script, str(vault)], check=False)
    assert result.returncode == 91
    assert (vault / ".transaction/manifest.json").exists()
    assert core.read_jkey(core.TOTP_FILE) == {"generation": "old"}
    assert core.read_jkey(core.PASSWORDS_FILE) == {"generation": "old"}
    assert not (vault / ".transaction").exists()


def test_crash_after_commit_keeps_new_generation(configured, monkeypatch):
    vault, _ = configured
    original = transaction.shutil.rmtree

    def fail(path):
        raise OSError("cleanup interrupted")

    monkeypatch.setattr(transaction.shutil, "rmtree", fail)
    with core._lock_vault():
        transaction.replace(str(vault), {"totp.jkey": b'{"new":true}'})
    monkeypatch.setattr(transaction.shutil, "rmtree", original)
    assert core.read_jkey(core.TOTP_FILE) == {"new": True}
    assert not (vault / ".transaction").exists()


def test_build_once_under_lock_and_upload_identical_bytes(configured, monkeypatch):
    vault, remote = configured
    backup.save_remotes({"a": {"url": str(remote)}, "b": {"url": str(remote) + "2"}})
    original_lock = core._lock_vault
    original_build = backup._build_snapshot
    original_put = LocalRemote.put
    locked = []
    builds = []

    @contextlib.contextmanager
    def tracked_lock(*a, **kw):
        with original_lock(*a, **kw):
            locked.append(True)
            try:
                yield
            finally:
                locked.pop()

    def build(*a):
        assert locked
        builds.append(True)
        return original_build(*a)

    def put(self, source, key, progress=None):
        if key.endswith(".tar.gz"):
            assert not locked
            (vault / "totp.jkey").write_bytes(b"changed during transfer")
        original_put(self, source, key, progress)

    monkeypatch.setattr(core, "_lock_vault", tracked_lock)
    monkeypatch.setattr(backup, "_build_snapshot", build)
    monkeypatch.setattr(LocalRemote, "put", put)
    backup._cmd_run(args(name=None))
    assert len(builds) == 1
    assert snapshot(remote).read_bytes() == snapshot(Path(str(remote) + "2")).read_bytes()


def test_remote_failure_does_not_skip_other_destinations(configured, monkeypatch):
    _, remote = configured
    backup.save_remotes({"a": {"url": str(remote)}, "b": {"url": str(remote) + "2"}})
    original = LocalRemote.put

    def fail(self, *a, **kw):
        if self.root == str(remote):
            raise JkeyError("remote unavailable")
        original(self, *a, **kw)

    monkeypatch.setattr(LocalRemote, "put", fail)
    with pytest.raises(JkeyError, match="remote unavailable"):
        backup._cmd_run(args(name=None))
    assert snapshot(Path(str(remote) + "2")).exists()


def test_corrupt_upload_cannot_prune_previous_backups(configured, monkeypatch):
    _, remote = configured
    backup._cmd_run(args())
    previous = snapshot(remote)
    original = LocalRemote.put

    def corrupt(self, source, key, progress=None):
        original(self, source, key, progress)
        if key.endswith(".tar.gz"):
            Path(self._path(key)).write_bytes(b"bad upload")

    monkeypatch.setattr(LocalRemote, "put", corrupt)
    with pytest.raises(JkeyError, match="checksum mismatch"):
        backup._cmd_run(args(keep=1))
    assert previous.exists()
    assert (remote / "LATEST").read_text().strip() == previous.name


def test_s3_listing_reads_all_pages():
    class Client:
        def list_objects_v2(self, **kw):
            if "ContinuationToken" not in kw:
                return {"Contents": [{"Key": "prefix/20260101-000000.tar.gz"}],
                        "IsTruncated": True, "NextContinuationToken": "next"}
            assert kw["ContinuationToken"] == "next"
            return {"Contents": [{"Key": "prefix/20260102-000000.tar.gz"}], "IsTruncated": False}

    remote = S3Remote("s3://bucket/prefix")
    remote._client = Client()
    assert remote.list_keys() == ["20260101-000000.tar.gz", "20260102-000000.tar.gz"]


def test_s3_broken_pagination_fails_instead_of_silently_truncating():
    class Client:
        def list_objects_v2(self, **kw):
            return {"IsTruncated": True}

    remote = S3Remote("s3://bucket/prefix")
    remote._client = Client()
    with pytest.raises(JkeyError, match="s3 list failed"):
        remote.list_keys()


def test_archive_file_manifest_detects_missing_members(configured, tmp_path):
    backup._cmd_run(args())
    _, remote = configured
    broken = tmp_path / "broken.tar.gz"
    with tarfile.open(snapshot(remote)) as source, tarfile.open(broken, "w:gz") as dest:
        for member in source.getmembers():
            if member.name != "passwords.jkey":
                dest.addfile(member, source.extractfile(member))
    out = tmp_path / "out"
    out.mkdir()
    with pytest.raises(JkeyError, match="file manifest mismatch"):
        backup._extract(str(broken), str(out))
    assert list(out.iterdir()) == []


@pytest.mark.parametrize("name,kind", [("sessions/secret", None), ("totp.jkey", tarfile.SYMTYPE),
                                      ("qr/pipe.jkey", tarfile.FIFOTYPE), ("../escape", None)])
def test_archive_rejects_unexpected_entries(tmp_path, name, kind):
    archive = tmp_path / "bad.tar.gz"
    with tarfile.open(archive, "w:gz") as tar:
        member = tarfile.TarInfo(name)
        if kind is not None:
            member.type = kind
        tar.addfile(member, io.BytesIO(b""))
    out = tmp_path / "out"
    out.mkdir()
    with pytest.raises(JkeyError):
        backup._extract(str(archive), str(out))
    assert list(out.iterdir()) == []



def test_recovery_drill_decrypts_data_and_qr_without_changing_live_vault(vault, tmp_path, monkeypatch, capsys):
    core.save_totp({"account": "JBSWY3DPEHPK3PXP"})
    core.save_qr_image("account", b"QR bytes")
    remote = tmp_path / "remote"
    backup.save_remotes({"nas": {"url": str(remote)}})
    backup._cmd_run(args())
    before = {p: open(p, "rb").read() for p in (core.TOTP_FILE, core.PASSWORDS_FILE, core.RECOVERY_FILE)}
    backup._cmd_verify(args(decrypt=True))
    assert "all vault files and QR images decrypted" in capsys.readouterr().out
    assert {p: open(p, "rb").read() for p in before} == before
    monkeypatch.setenv("JKEY_PASS", "wrong-password")
    with pytest.raises(JkeyError, match="Cannot decrypt"):
        backup._cmd_verify(args(decrypt=True))
    assert {p: open(p, "rb").read() for p in before} == before


def test_restore_keeps_encrypted_files_for_manual_password_resolution(vault, tmp_path, monkeypatch):
    core.encrypt_file(core.RECOVERY_FILE, {"recovery": ["codes"]}, "another-password")
    encrypted = open(core.RECOVERY_FILE, "rb").read()
    backup.save_remotes({"nas": {"url": str(tmp_path / "remote")}})
    backup._cmd_run(args())
    core.encrypt_file(core.RECOVERY_FILE, {}, "test-password")
    monkeypatch.setattr(core, "prompt_password", lambda *_: pytest.fail("Restore must not decrypt files"))
    monkeypatch.setattr("builtins.input", lambda *_: "y")
    backup._cmd_restore(args(into_vault=True))
    assert open(core.RECOVERY_FILE, "rb").read() == encrypted
    assert (tmp_path / "recovery.jkey.bak").exists()


def test_probe_reports_missing_delete_permission(tmp_path, monkeypatch):
    original = os.unlink

    def deny(path, *a, **kw):
        if ".probe-" in str(path):
            raise PermissionError("delete denied")
        return original(path, *a, **kw)

    monkeypatch.setattr(os, "unlink", deny)
    with pytest.raises(JkeyError, match="probe delete failed"):
        LocalRemote(str(tmp_path / "remote")).probe()


def test_s3_probe_reports_missing_delete_permission():
    class Client:
        def upload_fileobj(self, *a):
            pass

        def get_object(self, **kw):
            return {"Body": io.BytesIO(b"jkey probe")}

        def delete_object(self, **kw):
            raise PermissionError("delete denied")

    remote = S3Remote("s3://bucket/prefix")
    remote._client = Client()
    with pytest.raises(JkeyError, match="probe delete"):
        remote.probe()



def test_default_restore_restores_live_vault_in_one_command(vault, tmp_path, monkeypatch):
    backup.save_remotes({"nas": {"url": str(tmp_path / "remote")}})
    core.save_passwords({"site": "original"})
    backup._cmd_run(args())
    core.save_passwords({"site": "changed"})
    monkeypatch.setattr("builtins.input", lambda *_: "y")
    # No --into-vault and no output option are necessary.
    backup._cmd_restore(args())
    assert not core.is_unlocked()
    assert core.unlock_all("test-password")
    assert core.load_passwords() == {"site": "original"}


def test_explicit_output_only_extracts_without_live_restore(vault, tmp_path, monkeypatch):
    backup.save_remotes({"nas": {"url": str(tmp_path / "remote")}})
    core.save_passwords({"site": "original"})
    backup._cmd_run(args())
    core.save_passwords({"site": "changed"})

    def unexpected_prompt(*_):
        pytest.fail("Directory extraction must not prompt to replace the live vault")

    monkeypatch.setattr("builtins.input", unexpected_prompt)
    backup._cmd_restore(args(output=str(tmp_path / "out")))
    assert (tmp_path / "out/passwords.jkey").is_file()
    assert core.load_passwords() == {"site": "changed"}
