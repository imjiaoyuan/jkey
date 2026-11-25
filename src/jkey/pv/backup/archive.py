"""Snapshot archives: build, checksum, list, prune, and validated extraction."""

import hashlib
import io
import json
import os
import tarfile
import time
import uuid

from jkey.errors import JkeyError
from jkey.pv import core, transaction
from jkey.pv.backup.remotes.base import snapshot_stamp, valid_snapshot

# Vault files that go into a snapshot (relative names inside the tar). QR images are added as qr/<name>.jkey.
_VAULT_FILES = ("totp.jkey", "passwords.jkey", "recovery.jkey")


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


def _write_latest(tmpdir: str, stamp: str) -> str:
    p = os.path.join(tmpdir, "LATEST")
    with open(p, "w", encoding="ascii") as f:
        f.write(f"{stamp}.tar.gz\n")
    return p


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
