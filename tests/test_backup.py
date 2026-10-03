import io
import json
import os

import pytest

from jkey.errors import JkeyError

try:
    import botocore.exceptions  # noqa: F401

    HAVE_BOTOCORE = True
except ImportError:
    HAVE_BOTOCORE = False


@pytest.fixture
def backup_dir(tmp_path):
    d = tmp_path / "remote"
    d.mkdir()
    return str(d)


def _add_local_remote(name="nas", url=None):
    import jkey.pv.backup.core as bc

    bc.save_remotes({name: {"url": url}})


def _args(**kw):
    """Build a fake argparse namespace for backup subcommand impls."""
    base = {
        "name": None,
        "endpoint": None,
        "region": None,
        "keep": None,
        "access_key": None,
        "secret_key": None,
        "no_test": True,
        "force": False,
        "yes": False,
        "clear": False,
        "date": None,
        "output": None,
        "into_vault": False,
    }
    base.update(kw)
    return type("Args", (), base)()


def _fake_vault(vault):
    """Populate the initialized vault with real content so snapshots are non-trivial."""
    import jkey.pv.core as core

    core.save_totp({"github:me": "JBSWY3DPEHPK3PXP"})
    core.save_passwords({"my-site": "hunter2"})
    core.save_recovery({"github:me": ["1111-2222", "3333-4444"]})
    core.save_qr_image("github:me", b"fake-jpeg-bytes")


class TestConfig:
    def test_load_remotes_missing_file(self, vault_dir):
        import jkey.pv.backup.core as bc

        assert bc.load_remotes() == {}

    def test_save_and_load_roundtrip(self, vault_dir):
        import jkey.pv.backup.core as bc

        bc.save_remotes({"nas": {"url": "/tmp/x"}})
        assert bc.load_remotes() == {"nas": {"url": "/tmp/x"}}

    def test_remotes_file_permissions(self, vault_dir):
        import jkey.pv.backup.core as bc

        bc.save_remotes({})
        assert (os.stat(bc._remotes_file()).st_mode & 0o777) == 0o600

    def test_get_remote_unknown_raises(self, vault_dir):
        import jkey.pv.backup.core as bc

        with pytest.raises(JkeyError, match="not configured"):
            bc._get_remote("nope")

    def test_open_remote_unsupported_scheme(self, vault_dir):
        from jkey.pv.backup.remotes import open_remote

        with pytest.raises(JkeyError, match="Unsupported backup URL scheme"):
            open_remote({"url": "gdrive://x/y"})

    def test_redacted_masks_credentials(self, vault_dir):
        import jkey.pv.backup.core as bc

        red = bc._redacted({"url": "s3://b", "access_key": "AKIAIOSFODNN7EXAMPLE", "secret_key": "supersecret"})
        flat = json.dumps(red)
        assert "AKIAIOSFODNN7EXAMPLE" not in flat and "supersecret" not in flat
        assert red["access_key"].endswith("MPLE") and red["secret_key"].endswith("cret")


class TestParser:
    def _parser(self):
        from jkey.cli import _build_parser

        return _build_parser()

    def test_add_minimal(self):
        args = self._parser().parse_args(["backup", "add", "nas", "/mnt/nas"])
        assert (args.command, args.baction, args.name, args.url) == ("backup", "add", "nas", "/mnt/nas")
        assert args.no_test is False and args.force is False

    def test_add_s3_full(self):
        args = self._parser().parse_args(
            [
                "backup",
                "add",
                "aws",
                "s3://bkt/prefix",
                "--endpoint",
                "https://e",
                "--region",
                "r",
                "--access-key",
                "AK",
                "--secret-key",
                "SK",
                "-k",
                "3",
                "-f",
            ]
        )
        assert args.endpoint == "https://e" and args.region == "r"
        assert args.access_key == "AK" and args.secret_key == "SK"
        assert args.keep == 3 and args.force is True

    def test_run_all_and_single(self):
        p = self._parser()
        assert p.parse_args(["backup", "run"]).name is None
        assert p.parse_args(["backup", "run", "aws", "-k", "1"]).name == "aws"

    def test_restore_defaults(self):
        args = self._parser().parse_args(["backup", "restore", "aws"])
        assert args.date is None and args.output is None and args.into_vault is False

    def test_verify_date(self):
        assert self._parser().parse_args(["backup", "verify", "aws", "-d", "20250101-000000"]).date == "20250101-000000"


class TestRemotesCmd:
    def test_add_local_with_test(self, vault_dir, backup_dir, capsys):
        import jkey.pv.backup.core as bc

        bc._cmd_add(_args(name="nas", url=backup_dir, no_test=False))
        assert "Added backup remote 'nas'" in capsys.readouterr().out
        assert bc.load_remotes()["nas"]["url"] == backup_dir

    def test_add_duplicate_requires_force(self, vault_dir, backup_dir):
        import jkey.pv.backup.core as bc

        _add_local_remote("nas", backup_dir)
        with pytest.raises(JkeyError, match="already exists"):
            bc._cmd_add(_args(name="nas", url=backup_dir))
        assert bc.load_remotes()["nas"]["url"] == backup_dir

    def test_add_duplicate_with_force(self, vault_dir, backup_dir):
        import jkey.pv.backup.core as bc

        _add_local_remote("nas", "/old")
        bc._cmd_add(_args(name="nas", url=backup_dir, force=True))
        assert bc.load_remotes()["nas"]["url"] == backup_dir

    def test_add_inline_credentials_warns(self, vault_dir, backup_dir, capsys):
        import jkey.pv.backup.core as bc

        bc._cmd_add(_args(name="aws", url="s3://bkt", access_key="AK", secret_key="SK"))
        assert bc.load_remotes()["aws"]["secret_key"] == "SK"

    def test_add_access_key_without_secret_prompts(self, vault_dir, monkeypatch):
        import jkey.pv.backup.core as bc

        monkeypatch.setattr("jkey.pv.core.prompt_password", lambda *a: "SK-from-prompt")
        bc._cmd_add(_args(name="aws", url="s3://bkt", access_key="AK"))
        assert bc.load_remotes()["aws"]["secret_key"] == "SK-from-prompt"

    def test_add_access_key_empty_secret_raises(self, vault_dir, monkeypatch):
        import jkey.pv.backup.core as bc

        monkeypatch.setattr("jkey.pv.core.prompt_password", lambda *a: None)
        with pytest.raises(JkeyError, match="Secret key cannot be empty"):
            bc._cmd_add(_args(name="aws", url="s3://bkt", access_key="AK"))

    def test_add_s3_probe_failure_does_not_remove_config(self, vault_dir, monkeypatch):
        import sys

        import jkey.pv.backup.core as bc

        monkeypatch.setitem(sys.modules, "boto3", None)  # simulate boto3 not installed
        with pytest.raises(JkeyError, match="pip install jkey"):
            bc._cmd_add(_args(name="aws", url="s3://bkt", no_test=False))
        assert bc.load_remotes()["aws"]["url"] == "s3://bkt"

    def test_ls_masks_secrets(self, vault_dir, capsys):
        import jkey.pv.backup.core as bc

        bc.save_remotes({"aws": {"url": "s3://bkt", "access_key": "AKIAIOSFODNN7EXAMPLE", "secret_key": "topsecret"}})
        bc._cmd_ls(_args())
        out = capsys.readouterr().out
        assert "AKIAIOSFODNN7EXAMPLE" not in out and "topsecret" not in out
        assert "aws" in out

    def test_ls_empty(self, vault_dir, capsys):
        import jkey.pv.backup.core as bc

        bc._cmd_ls(_args())
        assert "No backup remotes" in capsys.readouterr().out

    def test_rm_with_yes(self, vault_dir, backup_dir, capsys):
        import jkey.pv.backup.core as bc

        _add_local_remote("nas", backup_dir)
        bc._cmd_rm(_args(name="nas", yes=True))
        assert bc.load_remotes() == {}
        assert "Removed" in capsys.readouterr().out

    def test_rm_confirm_no(self, vault_dir, backup_dir, monkeypatch):
        import jkey.pv.backup.core as bc

        _add_local_remote("nas", backup_dir)
        monkeypatch.setattr("builtins.input", lambda *_: "n")
        with pytest.raises(JkeyError, match="Cancelled"):
            bc._cmd_rm(_args(name="nas"))
        assert "nas" in bc.load_remotes()

    def test_rm_unknown(self, vault_dir):
        import jkey.pv.backup.core as bc

        with pytest.raises(JkeyError, match="not configured"):
            bc._cmd_rm(_args(name="x", yes=True))

    def test_cred_set_and_clear(self, vault_dir, monkeypatch):
        import jkey.pv.backup.core as bc

        bc.save_remotes({"aws": {"url": "s3://bkt"}})
        monkeypatch.setattr("builtins.input", lambda *_: "AK123")
        monkeypatch.setattr("jkey.pv.core.prompt_password", lambda *a: "SK456")
        bc._cmd_cred(_args(name="aws"))
        cfg = bc.load_remotes()["aws"]
        assert cfg["access_key"] == "AK123" and cfg["secret_key"] == "SK456"

        bc._cmd_cred(_args(name="aws", clear=True))
        cfg = bc.load_remotes()["aws"]
        assert "access_key" not in cfg and "secret_key" not in cfg

    def test_cred_empty_access_key_cancels(self, vault_dir, monkeypatch):
        import jkey.pv.backup.core as bc

        bc.save_remotes({"aws": {"url": "s3://bkt"}})
        monkeypatch.setattr("builtins.input", lambda *_: "")
        with pytest.raises(JkeyError, match="Cancelled"):
            bc._cmd_cred(_args(name="aws"))

    def test_cred_empty_secret_cancels(self, vault_dir, monkeypatch):
        import jkey.pv.backup.core as bc

        bc.save_remotes({"aws": {"url": "s3://bkt"}})
        monkeypatch.setattr("builtins.input", lambda *_: "AK123")
        monkeypatch.setattr("jkey.pv.core.prompt_password", lambda *a: "")
        with pytest.raises(JkeyError, match="Cancelled"):
            bc._cmd_cred(_args(name="aws"))

    def test_cred_eof_cancels_not_traceback(self, vault_dir, monkeypatch):
        """Regression: Ctrl-D at the access-key prompt must raise JkeyError, not EOFError."""
        import jkey.pv.backup.core as bc

        bc.save_remotes({"aws": {"url": "s3://bkt"}})

        def eof(*_a):
            raise EOFError

        monkeypatch.setattr("builtins.input", eof)
        with pytest.raises(JkeyError, match="Cancelled"):
            bc._cmd_cred(_args(name="aws"))

    def test_cred_non_s3_rejected(self, vault_dir, backup_dir):
        import jkey.pv.backup.core as bc

        _add_local_remote("nas", backup_dir)
        with pytest.raises(JkeyError, match="s3://"):
            bc._cmd_cred(_args(name="nas", access_key="AK", secret_key="SK"))

    def test_cmd_test_passes(self, vault_dir, backup_dir, capsys):
        import jkey.pv.backup.core as bc

        _add_local_remote("nas", backup_dir)
        bc._cmd_test(_args(name="nas"))
        assert "Connection test passed" in capsys.readouterr().out

    def test_cmd_test_unknown(self, vault_dir):
        import jkey.pv.backup.core as bc

        with pytest.raises(JkeyError, match="not configured"):
            bc._cmd_test(_args(name="ghost"))


class TestProbe:
    def test_local_probe_roundtrip_cleans_up(self, vault_dir, backup_dir):
        from jkey.pv.backup.remotes.local import LocalRemote

        LocalRemote(backup_dir).probe()
        assert os.listdir(backup_dir) == []

    def test_local_probe_unwritable(self, vault_dir, tmp_path):
        from jkey.pv.backup.remotes.local import LocalRemote

        (tmp_path / "f").write_text("blocker")  # file where a directory is needed
        with pytest.raises(JkeyError, match="not writable"):
            LocalRemote(str(tmp_path / "f" / "sub")).probe()

    def test_local_probe_readback_mismatch(self, vault_dir, backup_dir, monkeypatch):
        from jkey.pv.backup.remotes.local import LocalRemote

        real_open = open

        def bad_read(path, *a, **kw):
            fh = real_open(path, *a, **kw)
            if getattr(fh, "mode", "") == "rb" and path.endswith(".sha256"):
                return io.BytesIO(b"corrupted")
            return fh

        monkeypatch.setattr("builtins.open", bad_read)
        with pytest.raises(JkeyError, match="probe read-back mismatch"):
            LocalRemote(backup_dir).probe()

    def test_s3_probe_requires_boto3(self, vault_dir, monkeypatch):
        from jkey.pv.backup.remotes import s3

        monkeypatch.setitem(__import__("sys").modules, "boto3", None)
        with pytest.raises(JkeyError, match="pip install jkey"):
            s3.S3Remote("s3://bkt").probe()


class FakeS3Client:
    """In-memory S3 client covering upload/download/list/delete/get_object."""

    def __init__(self):
        self.objects = {}

    def upload_fileobj(self, fobj, bucket, key):
        self.objects[key] = fobj.read()

    def upload_file(self, path, bucket, key):
        with open(path, "rb") as f:
            self.objects[key] = f.read()

    def download_file(self, bucket, key, path):
        if key not in self.objects:
            raise self._not_found()
        with open(path, "wb") as f:
            f.write(self.objects[key])

    def get_object(self, Bucket, Key):
        if Key not in self.objects:
            raise self._not_found()
        return {"Body": io.BytesIO(self.objects[Key])}

    def list_objects_v2(self, Bucket, Prefix=""):
        return {"Contents": [{"Key": k} for k in sorted(self.objects) if k.startswith(Prefix)]}

    def delete_object(self, Bucket, Key):
        self.objects.pop(Key, None)

    @staticmethod
    def _not_found():
        import botocore.exceptions

        return botocore.exceptions.ClientError({"Error": {"Code": "404", "Message": "Not Found"}}, "HeadObject")


@pytest.mark.skipif(not HAVE_BOTOCORE, reason="botocore not installed")
class TestS3WithFakeClient:
    @pytest.fixture
    def s3_remote(self, vault_dir, backup_dir):
        from jkey.pv.backup.remotes.s3 import S3Remote

        r = S3Remote("s3://bkt/jkey")
        fake = FakeS3Client()
        r._client = fake
        return r, fake

    def test_probe_roundtrip(self, s3_remote):
        r, fake = s3_remote
        r.probe()
        assert fake.objects == {}

    def test_put_get_delete(self, s3_remote, tmp_path):
        r, fake = s3_remote
        src = tmp_path / "a.txt"
        src.write_bytes(b"hello")
        r.put(str(src), "20250101-000000.tar.gz")
        dest = tmp_path / "b.txt"
        r.get("20250101-000000.tar.gz", str(dest))
        assert dest.read_bytes() == b"hello"
        r.delete("20250101-000000.tar.gz")
        assert fake.objects == {}

    def test_get_missing_raises(self, s3_remote, tmp_path):
        r, _ = s3_remote
        with pytest.raises(JkeyError, match="download failed"):
            r.get("20990101-000000.tar.gz", str(tmp_path / "x"))

    def test_list_keys_filters_nested(self, s3_remote):
        r, fake = s3_remote
        fake.objects = {"jkey/LATEST": b"x", "jkey/20250101-000000.tar.gz": b"x", "jkey/sub/deep.tar.gz": b"x"}
        assert r.list_keys() == ["20250101-000000.tar.gz", "LATEST"]

    def test_invalid_s3_url(self):
        from jkey.pv.backup.remotes.s3 import S3Remote

        with pytest.raises(JkeyError, match="Invalid S3 URL"):
            S3Remote("s3:///noprefix")

    def test_error_message_masks_credentials(self, vault_dir, backup_dir):
        import botocore.exceptions

        from jkey.pv.backup.remotes.s3 import _wrap_s3_error

        e = botocore.exceptions.ClientError(
            {"Error": {"Code": "AccessDenied", "Message": "Access Denied for key AKIAIOSFODNN7EXAMPLE"}}, "PutObject"
        )
        err = _wrap_s3_error("upload", "s3://bkt", e)
        assert "access denied" in str(err)  # hint present
        assert "AKIAIOSFODNN7EXAMPLE" not in str(err)  # AKID-looking token from the message dropped

    def test_client_error_wrapping(self, s3_remote, tmp_path):
        r, fake = s3_remote

        def boom(*a, **kw):
            raise FakeS3Client._not_found()

        fake.upload_file = boom
        src = tmp_path / "a.txt"
        src.write_bytes(b"x")
        with pytest.raises(JkeyError, match="s3 upload failed.*bucket does not exist"):
            r.put(str(src), "20250101-000000.tar.gz")


class TestLifecycle:
    """Full run → snaps → restore → verify roundtrip over the local backend."""

    def test_backup_restore_roundtrip(self, vault, backup_dir, tmp_path, monkeypatch):
        import jkey.pv.backup.core as bc
        import jkey.pv.core as core

        _fake_vault(vault)
        _add_local_remote("nas", backup_dir)

        bc._cmd_run(_args(name="nas"))
        snaps = os.listdir(backup_dir)
        assert len([s for s in snaps if s.endswith(".tar.gz")]) == 1
        assert "LATEST" in snaps

        # Verify on remote
        bc._cmd_verify(_args(name="nas"))

        # Change the live vault, then restore into a directory and compare.
        core.save_totp({"github:me": "CHANGED"})
        bc._cmd_restore(_args(name="nas", output=str(tmp_path / "out")))

        restored_totp = os.path.join(str(tmp_path / "out"), "totp.jkey")
        restored = core.read_jkey(restored_totp)
        decrypted = core._aes().decrypt(restored, core.get_session_password())
        assert decrypted == {"github:me": "JBSWY3DPEHPK3PXP"}
        assert os.path.exists(os.path.join(str(tmp_path / "out"), "qr", "github_me.jkey"))

    def test_restore_into_vault_transactional(self, vault, backup_dir, monkeypatch, capsys):
        import jkey.pv.backup.core as bc
        import jkey.pv.core as core

        _fake_vault(vault)
        _add_local_remote("nas", backup_dir)
        bc._cmd_run(_args(name="nas"))

        # Wipe live data, then restore back from the snapshot.
        core.save_totp({"github:me": "WIPED"})
        core.save_passwords({})
        monkeypatch.setattr("builtins.input", lambda *_: "y")
        bc._cmd_restore(_args(name="nas", into_vault=True))
        assert "Vault updated" in capsys.readouterr().out

        # In-memory cache still shows pre-restore plaintext; verify from disk like a fresh process.
        core.lock()
        assert core.unlock_all("test-password")
        assert core.load_totp() == {"github:me": "JBSWY3DPEHPK3PXP"}
        assert core.load_passwords() == {"my-site": "hunter2"}

    def test_restore_into_vault_declined(self, vault, backup_dir, monkeypatch):
        import jkey.pv.backup.core as bc
        import jkey.pv.core as core

        _fake_vault(vault)
        _add_local_remote("nas", backup_dir)
        bc._cmd_run(_args(name="nas"))
        core.save_totp({"github:me": "CURRENT"})
        monkeypatch.setattr("builtins.input", lambda *_: "n")
        with pytest.raises(JkeyError, match="cancelled"):
            bc._cmd_restore(_args(name="nas", into_vault=True))
        assert core.load_totp() == {"github:me": "CURRENT"}

    def test_run_all_remotes_and_prune(self, vault, backup_dir, monkeypatch):

        _fake_vault(vault)
        import jkey.pv.backup.core as b2

        b2.save_remotes({"a": {"url": backup_dir + "1", "keep": 2}, "b": {"url": backup_dir + "2"}})
        os.makedirs(backup_dir + "1")
        os.makedirs(backup_dir + "2")

        stamps = iter(f"2025010{i}-000000" for i in range(1, 8))
        monkeypatch.setattr(b2, "_stamp", lambda: next(stamps))
        for _ in range(3):
            b2._cmd_run(_args())  # all remotes, keep from config
        files1 = os.listdir(backup_dir + "1")
        assert len([f for f in files1 if f.endswith(".tar.gz")]) == 2  # pruned to keep=2
        files2 = os.listdir(backup_dir + "2")
        assert len([f for f in files2 if f.endswith(".tar.gz")]) == 3  # 3 runs, default keep=5 never prunes

    def test_run_keep_override(self, vault, backup_dir, monkeypatch):
        import jkey.pv.backup.core as bc

        _fake_vault(vault)
        _add_local_remote("nas", backup_dir)
        stamps = iter(f"2025020{i}-000000" for i in range(1, 9))
        monkeypatch.setattr(bc, "_stamp", lambda: next(stamps))
        for _ in range(4):
            bc._cmd_run(_args(name="nas", keep=1))
        assert len([f for f in os.listdir(backup_dir) if f.endswith(".tar.gz")]) == 1

    def test_run_empty_vault_raises(self, vault_dir, backup_dir):
        import jkey.pv.backup.core as bc

        _add_local_remote("nas", backup_dir)
        with pytest.raises(JkeyError, match="Nothing to back up"):
            bc._cmd_run(_args(name="nas"))

    def test_run_unknown_remote(self, vault):
        import jkey.pv.backup.core as bc

        _fake_vault(vault)
        _add_local_remote("known", "/tmp/whatever")
        with pytest.raises(JkeyError, match="not configured"):
            bc._cmd_run(_args(name="ghost"))

    def test_run_no_remotes(self, vault):
        import jkey.pv.backup.core as bc

        _fake_vault(vault)
        with pytest.raises(JkeyError, match="No backup remotes"):
            bc._cmd_run(_args())

    def test_session_never_backed_up(self, vault, backup_dir):
        import jkey.pv.backup.core as bc

        _fake_vault(vault)
        _add_local_remote("nas", backup_dir)
        bc._cmd_run(_args(name="nas"))
        bc._cmd_restore(_args(name="nas", output=os.path.join(backup_dir, "_out")))
        restored = os.listdir(os.path.join(backup_dir, "_out"))
        assert ".session" not in restored and ".lock" not in restored

    def test_snaps_lists_and_empty(self, vault, backup_dir, capsys):
        import jkey.pv.backup.core as bc

        _fake_vault(vault)
        _add_local_remote("nas", backup_dir)
        bc._cmd_snaps(_args(name="nas"))
        assert "No snapshots" in capsys.readouterr().out
        bc._cmd_run(_args(name="nas"))
        bc._cmd_snaps(_args(name="nas"))
        out = capsys.readouterr().out
        assert ".tar.gz" in out

    def test_verify_detects_tampering(self, vault, backup_dir):
        import jkey.pv.backup.core as bc

        _fake_vault(vault)
        _add_local_remote("nas", backup_dir)
        bc._cmd_run(_args(name="nas"))
        snapshot = next(f for f in os.listdir(backup_dir) if f.endswith(".tar.gz"))
        # Tamper with the archive after upload
        with open(os.path.join(backup_dir, snapshot), "ab") as f:
            f.write(b"tampered")
        with pytest.raises(JkeyError, match="checksum mismatch"):
            bc._cmd_verify(_args(name="nas"))

    def test_verify_missing_snapshot_raises(self, vault, backup_dir):
        import jkey.pv.backup.core as bc

        _fake_vault(vault)
        _add_local_remote("nas", backup_dir)
        bc._cmd_run(_args(name="nas"))
        with pytest.raises(JkeyError, match="Snapshot not found"):
            bc._cmd_verify(_args(name="nas", date="20990101-000000"))

    def test_restore_specific_date(self, vault, backup_dir, monkeypatch, tmp_path):
        import jkey.pv.backup.core as bc

        _fake_vault(vault)
        _add_local_remote("nas", backup_dir)
        stamps = iter(["20250301-000000", "20250302-000000"])
        monkeypatch.setattr(bc, "_stamp", lambda: next(stamps))
        bc._cmd_run(_args(name="nas"))
        bc._cmd_run(_args(name="nas"))
        bc._cmd_restore(_args(name="nas", date="20250301-000000", output=str(tmp_path / "r1")))
        assert os.path.exists(str(tmp_path / "r1"))

    def test_restore_bad_date_rejected(self, vault, backup_dir):
        import jkey.pv.backup.core as bc

        _fake_vault(vault)
        _add_local_remote("nas", backup_dir)
        bc._cmd_run(_args(name="nas"))
        with pytest.raises(JkeyError, match="Invalid snapshot date"):
            bc._cmd_restore(_args(name="nas", date="../../etc"))

    def test_restore_traversal_member_rejected(self, vault, backup_dir, tmp_path):
        import tarfile

        import jkey.pv.backup.core as bc

        _fake_vault(vault)
        _add_local_remote("nas", backup_dir)
        bc._cmd_run(_args(name="nas"))
        snapshot = next(f for f in os.listdir(backup_dir) if f.endswith(".tar.gz"))
        stamp = snapshot[: -len(".tar.gz")]
        # Craft an archive with a path-traversal member and overwrite the remote snapshot.
        evil = tmp_path / "evil.tar.gz"
        with tarfile.open(evil, "w:gz") as tar:
            import io

            info = tarfile.TarInfo(name="../evil.txt")
            data = b"x"
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
        manifest = os.path.join(backup_dir, f"{stamp}.sha256")
        import hashlib

        with open(evil, "rb") as f:
            digest = hashlib.sha256(f.read()).hexdigest()
        with open(manifest, "w") as f:
            f.write(f"{digest}  {snapshot}\n")
        import shutil

        shutil.copyfile(evil, os.path.join(backup_dir, snapshot))
        with pytest.raises(JkeyError, match="escapes restore dir"):
            bc._cmd_restore(_args(name="nas", date=stamp, output=str(tmp_path / "out")))

    def test_verify_all_when_no_date(self, vault, backup_dir, capsys):
        import jkey.pv.backup.core as bc

        _fake_vault(vault)
        _add_local_remote("nas", backup_dir)
        bc._cmd_run(_args(name="nas"))
        bc._cmd_verify(_args(name="nas"))
        assert "OK:" in capsys.readouterr().out
