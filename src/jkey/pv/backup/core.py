"""Vault backup to S3, local directories, and existing rclone remotes.

Backs up the encrypted vault files as-is — no master password involved, nothing plaintext
ever leaves the machine. Remote layout per remote root:

    <stamp>.tar.gz   snapshot archive (totp.jkey, passwords.jkey, recovery.jkey, qr/*.jkey)
    <stamp>.sha256   one-line sha256 of the archive
    LATEST           name of the newest snapshot file

Remotes are configured in ~/.config/jkey/remotes.json (mode 600, same dir as the vault).
"""

import base64
import binascii
import hashlib
import io
import json
import os
import sys
import tarfile
import tempfile
import textwrap
import time
import uuid
from urllib.parse import urlparse

from jkey.errors import JkeyError
from jkey.pv import core, transaction
from jkey.pv.backup.remotes import open_remote
from jkey.pv.backup.remotes.base import _LATEST, snapshot_stamp, valid_snapshot


def _remotes_file() -> str:
    """Computed on call so tests that patch core.CONFIG_DIR never see a stale path."""
    return os.path.join(core.CONFIG_DIR, "remotes.json")


# Vault files that go into a snapshot (relative names inside the tar). QR images are added as qr/<name>.jkey.
_VAULT_FILES = ("totp.jkey", "passwords.jkey", "recovery.jkey")


# ---------------------------------------------------------------- config file


def load_remotes() -> dict:
    try:
        with open(_remotes_file(), encoding="utf-8") as f:
            data = json.loads("".join(line for line in f if not line.lstrip().startswith("#")))
        return data if isinstance(data, dict) else {}
    except FileNotFoundError:
        return {}
    except (json.JSONDecodeError, OSError) as e:
        raise JkeyError(f"cannot read backup config {_remotes_file()}: {e}") from e


def save_remotes(remotes: dict) -> None:
    text = (
        textwrap.dedent(
            """\
        # jkey backup remotes. Edit with: jkey remote init
        # One JSON object per remote. Fill url (s3://bucket/prefix or a local path),
        # rename the key to your remote's name, then delete its _comment.
        # Entries whose url is still empty are template placeholders — jkey ignores them.
        # endpoint/region: for S3-compatible providers (OSS, COS, MinIO, R2, B2); omit for AWS.
        # access_key/secret_key: leave both out to use the AWS default chain (~/.aws, env, IAM role).
        # keep: snapshots to retain on that remote (default 5).
        """
        )
        + json.dumps(remotes, indent=4, ensure_ascii=False)
        + "\n"
    )
    core.ensure_dir()
    core.write_secure_text(_remotes_file(), text, atomic=True)


def _get_remote(name: str, remotes: dict | None = None) -> dict:
    if name.startswith("rclone:"):
        return {"url": name}
    cfg = (remotes if remotes is not None else load_remotes()).get(name)
    if cfg is None:
        raise JkeyError(f"Backup remote '{name}' not configured. Run 'jkey remote init' to edit the config.")
    if not cfg.get("url"):
        raise JkeyError(f"Backup remote '{name}' is a template entry: fill in 'url' with 'jkey remote init'.")
    return cfg


def _mask_secret(value: str | None) -> str:
    return f"...{value[-4:]}" if value else "not set"


def _redacted(cfg: dict) -> dict:
    out = {k: v for k, v in cfg.items() if k not in ("access_key", "secret_key")}
    if cfg.get("access_key"):
        out["access_key"] = _mask_secret(cfg["access_key"])
        out["secret_key"] = _mask_secret(cfg["secret_key"])
    return out


# ------------------------------------------------------------------ snapshots


def _collect_vault_files() -> list[tuple[str, str]]:
    """(archive_name, absolute_path) pairs for every vault file that exists."""
    pairs = []
    for name in _VAULT_FILES:
        path = os.path.join(core.CONFIG_DIR, name)
        if os.path.exists(path):
            pairs.append((name, path))
    if os.path.isdir(core.QR_DIR):
        for img in sorted(os.listdir(core.QR_DIR)):
            if img.endswith(".jkey"):
                pairs.append((f"qr/{img}", os.path.join(core.QR_DIR, img)))
    if not pairs:
        raise JkeyError("Nothing to back up: vault is empty. Run 'jkey pv init' first.")
    return pairs


def _build_snapshot(pairs: list[tuple[str, str]], dest: str) -> str:
    metadata = {"version": 1, "files": {}}
    with tarfile.open(dest, "w:gz") as tar:
        for arcname, path in pairs:
            if not os.path.isfile(path) or os.path.islink(path):
                raise JkeyError(f"Refusing non-regular vault file: {path}")
            with open(path, "rb") as f:
                data = f.read()
            metadata["files"][arcname] = {"size": len(data), "sha256": hashlib.sha256(data).hexdigest()}
            info = tarfile.TarInfo(arcname)
            info.mode = 0o600
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
        payload = json.dumps(metadata, sort_keys=True).encode()
        info = tarfile.TarInfo("snapshot.json")
        info.mode = 0o600
        info.size = len(payload)
        tar.addfile(info, io.BytesIO(payload))
    return dest


def _sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _remote(remote_cfg: dict):
    return open_remote(remote_cfg)


def _snapshot_names(remote) -> list[str]:
    return sorted(n for n in remote.list_keys() if valid_snapshot(n))


def _completed_snapshot_names(remote):
    keys = set(remote.list_keys())
    return sorted(n for n in keys if valid_snapshot(n) and f"{snapshot_stamp(n)}.sha256" in keys)


def _latest_stamp(remote) -> str | None:
    # An interrupted upload must not supersede a completed recovery point.
    # Listing also avoids a stale LATEST pointer from a concurrent/older writer.
    snaps = _completed_snapshot_names(remote)
    return snapshot_stamp(snaps[-1]) if snaps else None


def _prune(remote, keep: int) -> list[str]:
    """Delete oldest snapshots beyond `keep`. Returns removed snapshot names."""
    if keep <= 0:
        return []
    snaps = _completed_snapshot_names(remote)
    to_remove = snaps[:-keep] if len(snaps) > keep else []
    for name in to_remove:
        remote.delete(name)
        remote.delete(f"{snapshot_stamp(name)}.sha256")
    return to_remove


def _stamp() -> str:
    return time.strftime("%Y%m%d-%H%M%S") + "-" + f"{time.time_ns():016x}{uuid.uuid4().hex[:16]}"


# ------------------------------------------------------------- subcommand impl


def _cmd_add(args) -> None:
    remotes = load_remotes()
    name = args.name
    if name in remotes and not args.force:
        raise JkeyError(f"Backup remote '{name}' already exists. Use --force to overwrite.")
    cfg: dict = {"url": args.url}
    if args.endpoint:
        cfg["endpoint"] = args.endpoint
    if args.region:
        cfg["region"] = args.region
    if args.keep is not None:
        cfg["keep"] = args.keep
    if args.access_key:
        cfg["access_key"] = args.access_key
        cfg["secret_key"] = args.secret_key or core.prompt_password("Secret key: ")
        if not cfg["secret_key"]:
            raise JkeyError("Secret key cannot be empty.")
    remotes[name] = cfg
    if urlparse_scheme(args.url) == "s3" and not urlparse(args.url).netloc.strip():
        raise JkeyError(
            f"Remote '{name}' has no bucket in its url — use s3://<bucket>/<prefix>. "
            "jkey does not create buckets; create it in the provider console first."
        )
    save_remotes(remotes)
    print(f"Added backup remote '{name}': {args.url}")

    if cfg.get("access_key"):
        print("Warning: credentials stored in plaintext in remotes.json", file=__import__("sys").stderr)

    if not args.no_test:
        _run_probe(name, cfg)


def _run_probe(name: str, cfg: dict) -> None:
    remote = _remote(cfg)
    remote.probe()
    print(f"Connection test passed: {name} ({cfg['url']})")


def _cmd_test(args) -> None:
    cfg = _get_remote(args.name)
    _run_probe(args.name, cfg)


def _cmd_ls(args) -> None:
    remotes = load_remotes()
    if not remotes:
        print(f"No backup remotes configured. Run 'jkey remote init' to create {_remotes_file()}.")
        return
    for name in sorted(remotes):
        cfg = remotes[name]
        print(f"{name}: {_redacted(cfg)}")


def _cmd_rm(args) -> None:
    remotes = load_remotes()
    if args.name not in remotes:
        raise JkeyError(f"Backup remote '{args.name}' not configured.")
    if not remotes[args.name].get("url"):
        del remotes[args.name]
        save_remotes(remotes)
        print(f"Removed template entry '{args.name}'.")
        return
    if not args.yes:
        try:
            response = input(f"Remove backup remote '{args.name}'? (y/N): ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print()
            raise JkeyError("Cancelled.")
        if response != "y":
            raise JkeyError("Cancelled.")
    del remotes[args.name]
    save_remotes(remotes)
    print(f"Removed backup remote '{args.name}'.")


def _cmd_cred(args) -> None:
    remotes = load_remotes()
    cfg = _get_remote(args.name, remotes)
    if args.clear:
        cfg.pop("access_key", None)
        cfg.pop("secret_key", None)
        remotes[args.name] = cfg
        save_remotes(remotes)
        print(f"Cleared inline credentials for '{args.name}' (will use AWS default chain).")
        return
    if urlparse_scheme(cfg["url"]) == "s3":
        try:
            access = args.access_key or input("Access key (empty to cancel): ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            raise JkeyError("Cancelled.")
        if not access:
            raise JkeyError("Cancelled.")
        secret = args.secret_key or core.prompt_password("Secret key: ")
        if not secret:
            raise JkeyError("Cancelled.")
        cfg["access_key"] = access
        cfg["secret_key"] = secret
    else:
        raise JkeyError("Inline credentials only apply to s3:// remotes.")
    remotes[args.name] = cfg
    save_remotes(remotes)
    print(f"Credentials updated for '{args.name}'.")


_INIT_TEMPLATE = {
    "example-s3": {
        "_comment": (
            "S3-compatible example. url = s3://<bucket>/<prefix> — the bucket must already exist "
            "(jkey does not create buckets; create it in the provider console first). "
            "endpoint/region for non-AWS providers, access_key + secret_key leave empty for the "
            "AWS default chain, then delete this _comment."
        ),
        "url": "",
        "endpoint": "",
        "region": "",
        "access_key": "",
        "secret_key": "",
        "keep": 5,
    },
    "example-local": {
        "_comment": "Local path example (NAS mount, USB drive). Rename the key, fill url, then delete this _comment.",
        "url": "",
    },
}


def _cmd_init(args) -> None:
    """Create the config with a template on first use; with a config present, just point at it."""
    if load_remotes():
        print(f"Backup config already exists: {_remotes_file()}")
        return
    save_remotes(_INIT_TEMPLATE)
    print(f"Template written to {_remotes_file()}. Edit it to configure a remote, then run 'jkey remote ls'.")


def urlparse_scheme(url: str) -> str:
    scheme = urlparse(url).scheme.lower()
    # Windows drive letters ("C:\..." or "C:/...") parse as a single-letter scheme — a local path.
    if len(scheme) == 1 and len(url) > 2 and url[1] == ":" and url[2] in ("\\", "/"):
        return ""
    return scheme


class _TransferProgress:
    """One-line transfer progress on the current terminal line.

    The total is provided by the caller (set_total); callbacks report bytes done.
    Silent when stdout is not a tty (pipes, cron).
    """

    def __init__(self, label: str):
        self.label = label
        self.total = None
        self.enabled = False
        self.last_len = 0

    def set_total(self, total: int | None) -> None:
        self.total = total
        self.enabled = total is not None and sys.stdout.isatty()

    def __call__(self, done: int) -> None:
        if not self.enabled:
            return
        pct = min(100, done * 100 // self.total)
        line = f"\r{self.label}: {pct:3d}% ({done}/{self.total} bytes)"
        pad = max(0, self.last_len - len(line))
        sys.stdout.write(line + " " * pad)
        sys.stdout.flush()
        self.last_len = len(line) + pad

    def finish(self) -> None:
        if self.enabled:
            sys.stdout.write(f"\r{self.label}: {self.total} bytes" + " " * max(0, self.last_len - 20) + "\n")
            sys.stdout.flush()

    def abort(self) -> None:
        if self.enabled:
            sys.stdout.write("\n")
            sys.stdout.flush()


def _cmd_run(args) -> None:
    remotes = load_remotes()
    if args.name:
        remotes[args.name] = _get_remote(args.name, remotes)
        names = [args.name]
    else:
        names = [n for n in sorted(remotes) if remotes[n].get("url")]
        if not names:
            raise JkeyError("No backup remote configured yet. Run 'jkey remote init' and fill in an entry's url.")

    # Freeze one complete generation under the vault lock, then upload the same bytes everywhere.
    stamp = _stamp()
    failures = []
    with tempfile.TemporaryDirectory() as tmpdir:
        archive = os.path.join(tmpdir, f"{stamp}.tar.gz")
        with core._lock_vault(shared=True):
            pairs = _collect_vault_files()
            _build_snapshot(pairs, archive)
        manifest = os.path.join(tmpdir, f"{stamp}.sha256")
        with open(manifest, "w", encoding="ascii") as f:
            f.write(f"{_sha256(archive)}  {stamp}.tar.gz\n")
        # Check the actual archive before publishing or pruning old snapshots.
        checked = os.path.join(tmpdir, "checked")
        os.mkdir(checked, mode=0o700)
        _extract(archive, checked)
        for name in names:
            cfg = remotes[name]
            try:
                keep = args.keep if args.keep is not None else cfg.get("keep", 5)
                if not isinstance(keep, int) or isinstance(keep, bool) or keep < 0:
                    raise JkeyError("keep must be a non-negative integer (0 keeps all snapshots)")
                remote = _remote(cfg)
                size = os.path.getsize(archive)
                progress = _TransferProgress(f"Uploading {stamp}.tar.gz")
                progress.set_total(size)
                try:
                    remote.put(archive, f"{stamp}.tar.gz", progress=progress)
                except BaseException:
                    progress.abort()
                    raise
                progress.finish()
                # Read back before declaring success or deleting any previous recovery points.
                downloaded = os.path.join(tmpdir, "readback.tar.gz")
                remote.get(f"{stamp}.tar.gz", downloaded)
                _verify_archive(downloaded, manifest, f"{stamp}.tar.gz")
                # Publishing the manifest marks a snapshot complete only after read-back succeeds.
                remote.put(manifest, f"{stamp}.sha256")
                remote_manifest = os.path.join(tmpdir, "readback.sha256")
                remote.get(f"{stamp}.sha256", remote_manifest)
                _verify_archive(downloaded, remote_manifest, f"{stamp}.tar.gz")
                remote.put(_write_latest(tmpdir, stamp), _LATEST)
                removed = _prune(remote, keep)
                print(f"Backed up to {name} ({cfg['url']}): {stamp}.tar.gz ({len(pairs)} files), "
                      f"verified; pruned {len(removed)} old snapshot(s)")
            except (JkeyError, OSError) as e:
                failures.append(f"{name}: {e}")
                print(f"Backup failed for {name}: {e}", file=sys.stderr)
    if failures:
        raise JkeyError("Backup failed for " + "; ".join(failures))


def _write_latest(tmpdir: str, stamp: str) -> str:
    p = os.path.join(tmpdir, "LATEST")
    with open(p, "w", encoding="ascii") as f:
        f.write(f"{stamp}.tar.gz\n")
    return p


def _cmd_snaps(args) -> None:
    cfg = _get_remote(args.name)
    remote = _remote(cfg)
    snaps = _snapshot_names(remote)
    if not snaps:
        print(f"No snapshots on '{args.name}' yet. Run 'jkey backup {args.name}'.")
        return
    for n in snaps:
        print(n)


def _verify_archive(archive: str, manifest_path: str, snapshot: str) -> None:
    expected = ""
    try:
        with open(manifest_path, encoding="ascii") as f:
            expected = f.read().split()[0]
    except (OSError, IndexError, UnicodeError):
        raise JkeyError(f"corrupt or missing manifest for {snapshot}")
    actual = _sha256(archive)
    if actual != expected:
        raise JkeyError(f"checksum mismatch for {snapshot}: expected {expected}, got {actual}")


def _cmd_restore(args) -> None:
    cfg = _get_remote(args.name)
    remote = _remote(cfg)
    snapshot = f"{args.date}.tar.gz" if args.date else None

    if snapshot is None:
        stamp = _latest_stamp(remote)
        if stamp is None:
            raise JkeyError(f"No snapshots on '{args.name}'. Run 'jkey backup <remote>' first.")
        snapshot = f"{stamp}.tar.gz"
    elif not valid_snapshot(snapshot):
        raise JkeyError(f"Invalid snapshot date: {args.date!r} (use the snapshot ID shown by remote snaps)")

    tmpdir = tempfile.mkdtemp(prefix="jkey-restore-")
    try:
        archive = os.path.join(tmpdir, snapshot)
        manifest = os.path.join(tmpdir, f"{snapshot_stamp(snapshot)}.sha256")
        progress = _TransferProgress(f"Downloading {snapshot}")
        progress.set_total(remote.size(snapshot))
        try:
            remote.get(snapshot, archive, progress=progress)
        except BaseException:
            progress.abort()
            raise
        progress.finish()
        remote.get(f"{snapshot_stamp(snapshot)}.sha256", manifest)
        _verify_archive(archive, manifest, snapshot)

        into_vault = not args.output
        out_dir = args.output or os.path.join(tmpdir, "extracted")
        extracted = os.path.join(tmpdir, "verified")
        os.mkdir(extracted, mode=0o700)
        _extract(archive, extracted)
        if into_vault:
            _confirm_and_write_into_vault(extracted)
        else:
            _restore_files(extracted, out_dir)
            print(f"Restored {args.name}:{snapshot} to {out_dir}")
    finally:
        import shutil

        shutil.rmtree(tmpdir, ignore_errors=True)


def _extract(archive: str, out_dir: str) -> None:
    """Validate names, types, bounds and file manifest before writing any vault data."""
    base = os.path.realpath(out_dir)
    try:
        with tarfile.open(archive, "r:gz") as tar:
            members = tar.getmembers()
            if len(members) > 10000 or sum(m.size for m in members) > 512 * 1024 * 1024:
                raise JkeyError("Snapshot exceeds restore size or file-count limits")
            names = set()
            contents = {}
            for member in members:
                name = member.name
                target = os.path.realpath(os.path.join(base, name))
                if not target.startswith(base + os.sep):
                    raise JkeyError(f"snapshot entry escapes restore dir — refusing: {name}")
                if member.isdir() and name == "qr":
                    continue  # Legacy archives included the directory entry.
                if not member.isfile() or name in names:
                    raise JkeyError(f"snapshot contains a link, special file or duplicate — refusing: {name}")
                if name != "snapshot.json":
                    transaction._target(base, name)
                names.add(name)
                with tar.extractfile(member) as f:
                    contents[name] = f.read()
            payload = contents.pop("snapshot.json", None)
            if payload is not None:
                metadata = json.loads(payload)
                if metadata.get("version") != 1 or not isinstance(metadata.get("files"), dict):
                    raise JkeyError("Unsupported or corrupt snapshot format")
                expected = {name: {"size": len(data), "sha256": hashlib.sha256(data).hexdigest()}
                            for name, data in contents.items()}
                if metadata["files"] != expected:
                    raise JkeyError("Snapshot file manifest mismatch")
            if not any(name in contents for name in _VAULT_FILES):
                raise JkeyError("Snapshot contains no vault files")
            for name, data in contents.items():
                dest = transaction._target(base, name)
                dest.parent.mkdir(mode=0o700, exist_ok=True)
                # Exclusive creation prevents merging a snapshot with pre-existing files.
                fd = os.open(dest, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(fd, "wb") as f:
                    f.write(data)
    except (tarfile.TarError, OSError, ValueError, TypeError, AttributeError) as e:
        raise JkeyError(f"Cannot extract snapshot: {e}") from e


def _decrypt_snapshot(out_dir, password):
    """Verify every encrypted payload, including QR images, without touching the live vault."""
    try:
        files = [os.path.join(out_dir, n) for n in _VAULT_FILES if os.path.isfile(os.path.join(out_dir, n))]
        qr_dir = os.path.join(out_dir, "qr")
        if os.path.isdir(qr_dir):
            files.extend(os.path.join(qr_dir, n) for n in os.listdir(qr_dir) if n.endswith(".jkey"))
        for path in files:
            with open(path, encoding="utf-8") as f:
                data = core._aes().decrypt(json.load(f), password)
            if not isinstance(data, dict):
                return False
            if os.path.dirname(path) == qr_dir:
                base64.b64decode(data["raw"], validate=True)
        return bool(files)
    except (OSError, ValueError, KeyError, TypeError, binascii.Error):
        return False


def _authenticate_snapshot(out_dir, password=None):
    candidate = password or core.password_from_env() or core.get_session_password()
    if candidate is None and core._ticket(core._session_file()) is not None:
        candidate = core.session_store.load(core._session_file())
    if candidate and _decrypt_snapshot(out_dir, candidate):
        return candidate
    if core.password_from_env():
        raise JkeyError("Cannot decrypt every snapshot file with JKEY_PASS; vault not changed.")
    candidate = core.prompt_password("Snapshot master password: ")
    if not candidate or not _decrypt_snapshot(out_dir, candidate):
        raise JkeyError("Cannot decrypt every snapshot file; vault not changed.")
    return candidate


def _restore_files(source_dir, target_dir):
    """Copy encrypted files, retaining local-only data and preserving every conflicting version."""
    os.makedirs(target_dir, mode=0o700, exist_ok=True)
    names = [n for n in _VAULT_FILES if os.path.isfile(os.path.join(source_dir, n))]
    qr = os.path.join(source_dir, "qr")
    if os.path.isdir(qr):
        names.extend(f"qr/{n}" for n in sorted(os.listdir(qr)) if n.endswith(".jkey"))
    for name in names:
        src = transaction._target(source_dir, name)
        dest = transaction._target(target_dir, name)
        dest.parent.mkdir(mode=0o700, exist_ok=True)
        saved = transaction.preserve_and_write(dest, src.read_bytes())
        if saved:
            print(f"Kept previous file: {saved}")


def _confirm_and_write_into_vault(out_dir: str) -> None:
    try:
        response = input("Restore files, keeping conflicts as .bak? (y/N): ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        print()
        raise JkeyError("Restore cancelled.") from None
    if response != "y":
        raise JkeyError("Restore cancelled.")
    _write_into_vault(out_dir, [])
    print("Vault restored. Conflicts are kept as .bak files for manual resolution.")


def _write_into_vault(out_dir: str, files: list[str]) -> None:
    core.ensure_dir()
    try:
        with core._lock_vault():
            try:
                _restore_files(out_dir, core.CONFIG_DIR)
            finally:
                # Some files may already have changed even when a later file fails.
                core.lock()
    except OSError as e:
        raise JkeyError(f"failed to restore into vault: {e}") from e


def _cmd_verify(args) -> None:
    cfg = _get_remote(args.name)
    remote = _remote(cfg)
    if args.date:
        snapshot = f"{args.date}.tar.gz"
        if not valid_snapshot(snapshot):
            raise JkeyError(f"Invalid snapshot date: {args.date!r} (use the snapshot ID shown by remote snaps)")
        if snapshot not in _snapshot_names(remote):
            raise JkeyError(f"Snapshot not found on '{args.name}': {snapshot}")
        targets = [snapshot]
    else:
        targets = _snapshot_names(remote)
        if not targets:
            raise JkeyError(f"No snapshots on '{args.name}'.")
    password = None
    for snapshot in targets:
        with tempfile.TemporaryDirectory() as tmpdir:
            archive = os.path.join(tmpdir, snapshot)
            manifest = os.path.join(tmpdir, f"{snapshot_stamp(snapshot)}.sha256")
            progress = _TransferProgress(f"Downloading {snapshot}")
            progress.set_total(remote.size(snapshot))
            try:
                remote.get(snapshot, archive, progress=progress)
            except BaseException:
                progress.abort()
                raise
            progress.finish()
            remote.get(f"{snapshot_stamp(snapshot)}.sha256", manifest)
            _verify_archive(archive, manifest, snapshot)
            checked = os.path.join(tmpdir, "checked")
            os.mkdir(checked, mode=0o700)
            _extract(archive, checked)
            if getattr(args, "decrypt", False):
                password = _authenticate_snapshot(checked, password)
        suffix = " (all vault files and QR images decrypted)" if getattr(args, "decrypt", False) else ""
        print(f"OK: {snapshot}{suffix}")


# ------------------------------------------------------------------ CLI entry


def cmd_backup(args):
    action = args.action
    if action == "add":
        _cmd_add(args)
    elif action == "init":
        _cmd_init(args)
    elif action == "ls":
        _cmd_ls(args)
    elif action == "rm":
        _cmd_rm(args)
    elif action == "cred":
        _cmd_cred(args)
    elif action == "test":
        _cmd_test(args)
    elif action == "run":
        _cmd_run(args)
    elif action == "snaps":
        _cmd_snaps(args)
    elif action == "restore":
        _cmd_restore(args)
    elif action == "verify":
        _cmd_verify(args)
    else:
        raise JkeyError(f"Unknown backup action: {action}")
