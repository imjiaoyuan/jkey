"""Recoverable multi-file vault updates. Call only while holding the vault lock."""

import contextlib
import json
import os
import shutil
import tempfile
import time
import uuid
from pathlib import Path

from jkey.errors import JkeyError


def sync_dir(path):
    if os.name != "nt":
        fd = os.open(path, os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)


def stage(path, data):
    parent = os.path.dirname(path)
    fd, tmp = tempfile.mkstemp(prefix=".jkey-", dir=parent)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
    except BaseException:
        os.unlink(tmp)
        raise
    return tmp


def write(path, data):
    tmp = stage(str(path), data)
    try:
        os.replace(tmp, path)
        sync_dir(os.path.dirname(path))
    finally:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(tmp)


def _target(root, name):
    parts = name.split("/")
    if name not in ("totp.jkey", "passwords.jkey", "recovery.jkey") and not (
        len(parts) == 2 and parts[0] == "qr" and parts[1].endswith(".jkey")
        and parts[1] not in (".jkey", "..jkey") and "\\" not in name
    ):
        raise JkeyError(f"Invalid transaction path: {name!r}")
    target = Path(root).joinpath(*parts)
    if target.is_symlink() or target.parent.is_symlink():
        raise JkeyError(f"Refusing symlink in vault: {name}")
    return target


def recover(root):
    journal = Path(root) / ".transaction"
    if not journal.exists():
        return
    manifest = journal / "manifest.json"
    if not manifest.exists():
        # No live files are touched until the manifest is durable.
        shutil.rmtree(journal)
        return
    try:
        state = json.loads(manifest.read_text(encoding="utf-8"))
        if state["state"] != "committed":
            for i, entry in enumerate(state["files"]):
                dest = _target(root, entry["name"])
                if entry["existed"]:
                    write(dest, (journal / f"old-{i}").read_bytes())
                else:
                    dest.unlink(missing_ok=True)
                    sync_dir(dest.parent)
        shutil.rmtree(journal)
        sync_dir(root)
    except (OSError, ValueError, KeyError, TypeError) as e:
        raise JkeyError(f"Cannot recover vault transaction; recovery files retained at {journal}: {e}") from e


def replace(root, updates):
    """updates maps relative vault names to bytes (or None to delete)."""
    recover(root)
    journal = Path(root) / ".transaction"
    journal.mkdir(mode=0o700)
    state = {"state": "prepared", "files": []}
    try:
        for i, (name, data) in enumerate(updates.items()):
            dest = _target(root, name)
            dest.parent.mkdir(mode=0o700, exist_ok=True)
            existed = dest.exists()
            if existed:
                write(journal / f"old-{i}", dest.read_bytes())
            if data is not None:
                write(journal / f"new-{i}", data)
            state["files"].append({"name": name, "existed": existed, "delete": data is None})
        write(journal / "manifest.json", json.dumps(state).encode())
        sync_dir(root)
        for i, entry in enumerate(state["files"]):
            dest = _target(root, entry["name"])
            if entry["delete"]:
                dest.unlink(missing_ok=True)
            else:
                os.replace(journal / f"new-{i}", dest)
            sync_dir(dest.parent)
        state["state"] = "committed"
        write(journal / "manifest.json", json.dumps(state).encode())
    except BaseException:
        recover(root)
        raise
    # A committed journal can safely be cleaned up on the next access as well.
    with contextlib.suppress(OSError):
        shutil.rmtree(journal)
        sync_dir(root)



def preserve_and_write(path, data):
    """Keep a changed existing file as .bak before atomically publishing its replacement.

    The caller serializes concurrent vault writers. Backups use exclusive creation so
    existing backup versions are never overwritten, including after an interrupted run.
    """
    path = Path(path)
    old = path.read_bytes() if path.exists() else None
    if old == data:
        return None
    tmp = stage(str(path), data)
    saved = None
    try:
        if old is not None:
            saved = Path(str(path) + ".bak")
            while True:
                try:
                    fd = os.open(saved, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                    break
                except FileExistsError:
                    saved = Path(f"{path}.{time.strftime('%Y%m%d-%H%M%S')}-{uuid.uuid4().hex[:8]}.bak")
            with os.fdopen(fd, "wb") as f:
                f.write(old)
                f.flush()
                os.fsync(f.fileno())
            sync_dir(path.parent)
        os.replace(tmp, path)
        sync_dir(path.parent)
    finally:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(tmp)
    return saved
