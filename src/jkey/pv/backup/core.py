"""Vault backup to S3 / S3-compatible / local remotes.

Backs up the encrypted vault files as-is — no master password involved, nothing plaintext
ever leaves the machine. Remote layout per remote root:

    <stamp>.tar.gz   snapshot archive (totp.jkey, passwords.jkey, recovery.jkey, qr/*.jkey)
    <stamp>.sha256   one-line sha256 of the archive
    LATEST           name of the newest snapshot file

Remotes are configured in ~/.config/jkey/remotes.json (mode 600, same dir as the vault).
"""

import hashlib
import json
import os
import sys
import tarfile
import tempfile
import textwrap
import time
from urllib.parse import urlparse

from jkey.errors import JkeyError
from jkey.pv import core
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
        with open(_remotes_file()) as f:
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
        # jkey backup remotes. Edit with: jkey backup init
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
    core.write_secure_text(_remotes_file(), text, atomic=True)


def _get_remote(name: str, remotes: dict | None = None) -> dict:
    cfg = (remotes if remotes is not None else load_remotes()).get(name)
    if cfg is None:
        raise JkeyError(f"Backup remote '{name}' not configured. Run 'jkey backup init' to edit the config.")
    if not cfg.get("url"):
        raise JkeyError(f"Backup remote '{name}' is a template entry: fill in 'url' with 'jkey backup init'.")
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
    with tarfile.open(dest, "w:gz") as tar:
        for arcname, path in pairs:
            tar.add(path, arcname=arcname)
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


def _latest_stamp(remote) -> str | None:
    """Prefer the LATEST pointer; fall back to the newest snapshot on the remote."""
    import contextlib

    tmp = tempfile.NamedTemporaryFile(delete=False)
    tmp.close()
    try:
        with contextlib.suppress(Exception):
            remote.get(_LATEST, tmp.name)
            with open(tmp.name) as f:
                name = f.read().strip()
            if valid_snapshot(name) and name in _snapshot_names(remote):
                return snapshot_stamp(name)
        snaps = _snapshot_names(remote)
        return snapshot_stamp(snaps[-1]) if snaps else None
    finally:
        with contextlib.suppress(OSError):
            os.unlink(tmp.name)


def _prune(remote, keep: int) -> list[str]:
    """Delete oldest snapshots beyond `keep`. Returns removed snapshot names."""
    if keep <= 0:
        return []
    snaps = _snapshot_names(remote)
    to_remove = snaps[:-keep] if len(snaps) > keep else []
    for name in to_remove:
        remote.delete(name)
        remote.delete(f"{snapshot_stamp(name)}.sha256")
    return to_remove


def _stamp() -> str:
    return time.strftime("%Y%m%d-%H%M%S")


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
        print(f"No backup remotes configured. Run 'jkey backup init' to create {_remotes_file()}.")
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
    print(f"Template written to {_remotes_file()}. Edit it to configure a remote, then run 'jkey backup ls'.")


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
        _get_remote(args.name, remotes)
        names = [args.name]
    else:
        names = [n for n in sorted(remotes) if remotes[n].get("url")]
        if not names:
            raise JkeyError("No backup remote configured yet. Run 'jkey backup init' and fill in an entry's url.")

    pairs = _collect_vault_files()
    stamp = _stamp()
    for name in names:
        cfg = remotes[name]
        remote = _remote(cfg)
        with tempfile.TemporaryDirectory() as tmpdir:
            archive = _build_snapshot(pairs, os.path.join(tmpdir, f"{stamp}.tar.gz"))
            digest = _sha256(archive)
            with open(os.path.join(tmpdir, f"{stamp}.sha256"), "w") as f:
                f.write(f"{digest}  {stamp}.tar.gz\n")
            size = os.path.getsize(archive)
            progress = _TransferProgress(f"Uploading {stamp}.tar.gz")
            progress.set_total(size)
            try:
                remote.put(archive, f"{stamp}.tar.gz", progress=progress)
            except BaseException:
                progress.abort()
                raise
            progress.finish()
            remote.put(os.path.join(tmpdir, f"{stamp}.sha256"), f"{stamp}.sha256")
            remote.put(_write_latest(tmpdir, stamp), _LATEST)
        keep = args.keep if args.keep is not None else cfg.get("keep", 5)
        removed = _prune(remote, keep)
        msg = f"Backed up to {name} ({cfg['url']}): {stamp}.tar.gz ({len(pairs)} files)"
        if removed:
            msg += f", pruned {len(removed)} old snapshot(s)"
        print(msg)


def _write_latest(tmpdir: str, stamp: str) -> str:
    p = os.path.join(tmpdir, "LATEST")
    with open(p, "w") as f:
        f.write(f"{stamp}.tar.gz\n")
    return p


def _cmd_snaps(args) -> None:
    cfg = _get_remote(args.name)
    remote = _remote(cfg)
    snaps = _snapshot_names(remote)
    if not snaps:
        print(f"No snapshots on '{args.name}' yet. Run 'jkey backup run {args.name}'.")
        return
    for n in snaps:
        print(n)


def _verify_archive(archive: str, manifest_path: str, snapshot: str) -> None:
    expected = ""
    try:
        with open(manifest_path) as f:
            expected = f.read().split()[0]
    except (OSError, IndexError):
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
            raise JkeyError(f"No snapshots on '{args.name}'. Run 'jkey backup run' first.")
        snapshot = f"{stamp}.tar.gz"
    elif not valid_snapshot(snapshot):
        raise JkeyError(f"Invalid snapshot date: {args.date!r} (expected YYYYMMDD-HHMMSS)")

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
        try:
            remote.get(f"{snapshot_stamp(snapshot)}.sha256", manifest)
        except JkeyError:
            manifest = None  # older snapshot without a manifest — skip verification
        if manifest:
            _verify_archive(archive, manifest, snapshot)

        out_dir = args.output
        if not out_dir:
            out_dir = os.path.join(os.getcwd(), f"jkey-restore-{snapshot_stamp(snapshot)}")
        os.makedirs(out_dir, mode=0o700, exist_ok=True)
        _extract(archive, out_dir)
        print(f"Restored {args.name}:{snapshot} to {out_dir}")

        if args.into_vault:
            _confirm_and_write_into_vault(out_dir)
    finally:
        import shutil

        shutil.rmtree(tmpdir, ignore_errors=True)


def _extract(archive: str, out_dir: str) -> None:
    """Extract a snapshot tar, refusing members that escape out_dir (path traversal)."""
    base = os.path.realpath(out_dir)
    with tarfile.open(archive, "r:gz") as tar:
        for member in tar.getmembers():
            if member.issym() or member.islnk():
                raise JkeyError(f"snapshot contains a link — refusing: {member.name}")
            target = os.path.realpath(os.path.join(base, member.name))
            if not (target == base or target.startswith(base + os.sep)):
                raise JkeyError(f"snapshot entry escapes restore dir — refusing: {member.name}")
            if member.isdev():
                raise JkeyError(f"snapshot contains a device file — refusing: {member.name}")
        # `filter` was added in 3.11 and only backported to 3.10.12+; older 3.10.x ignores it.
        # The manual checks above already cover what filter="data" enforces.
        if sys.version_info >= (3, 11):
            tar.extractall(out_dir, filter="data")
        else:
            tar.extractall(out_dir)


def _confirm_and_write_into_vault(out_dir: str) -> None:
    files = [n for n in _VAULT_FILES if os.path.exists(os.path.join(out_dir, n))]
    if not files:
        raise JkeyError("Snapshot contains no vault files.")
    qr_dir = os.path.join(out_dir, "qr")
    qr_count = len(os.listdir(qr_dir)) if os.path.isdir(qr_dir) else 0
    print("This will overwrite the current vault with:")
    for n in files:
        print(f"  {n}")
    if qr_count:
        print(f"  qr/ ({qr_count} images)")
    try:
        response = input("Overwrite the current vault? (y/N): ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        print()
        raise JkeyError("Restore cancelled.")
    if response != "y":
        raise JkeyError("Restore cancelled.")
    _write_into_vault(out_dir, files)
    # Vault files were replaced behind the caches' back: drop every terminal's ticket and
    # this process's in-memory copies, so the next command re-authenticates and re-decrypts
    # from the restored files instead of silently writing the stale cache back over them.
    core.lock()
    print("Vault updated. Run 'jkey pv status' and any command to unlock and verify.")


def _write_into_vault(out_dir: str, files: list[str]) -> None:
    """Transactional replace: stage everything, then commit with os.replace."""
    core.ensure_dir()
    staged = []
    try:
        for name in files:
            src = os.path.join(out_dir, name)
            data = open(src, "rb").read()
            staged.append(
                (os.path.join(core.CONFIG_DIR, name), core._stage_write(os.path.join(core.CONFIG_DIR, name), data))
            )
        qr_src = os.path.join(out_dir, "qr")
        if os.path.isdir(qr_src):
            os.makedirs(core.QR_DIR, mode=0o700, exist_ok=True)
            for img in sorted(os.listdir(qr_src)):
                if not img.endswith(".jkey"):
                    continue
                data = open(os.path.join(qr_src, img), "rb").read()
                dest = os.path.join(core.QR_DIR, img)
                staged.append((dest, core._stage_write(dest, data)))
        with core._lock_vault():
            for dest, tmp in staged:
                os.replace(tmp, dest)
    except OSError as e:
        for _dest, tmp in staged:
            try:
                os.unlink(tmp)
            except OSError:
                pass
        raise JkeyError(f"failed to restore into vault: {e}") from e


def _cmd_verify(args) -> None:
    cfg = _get_remote(args.name)
    remote = _remote(cfg)
    if args.date:
        snapshot = f"{args.date}.tar.gz"
        if not valid_snapshot(snapshot):
            raise JkeyError(f"Invalid snapshot date: {args.date!r} (expected YYYYMMDD-HHMMSS)")
        if snapshot not in _snapshot_names(remote):
            raise JkeyError(f"Snapshot not found on '{args.name}': {snapshot}")
        targets = [snapshot]
    else:
        targets = _snapshot_names(remote)
        if not targets:
            raise JkeyError(f"No snapshots on '{args.name}'.")
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
        print(f"OK: {snapshot}")


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
