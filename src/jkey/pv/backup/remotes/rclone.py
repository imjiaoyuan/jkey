"""Use existing rclone remotes without importing or copying their credentials."""

import json
import os
import subprocess
import tempfile
import uuid

from jkey.errors import JkeyError
from jkey.pv.backup.remotes.base import Remote, safe_remote_key


class RcloneRemote(Remote):
    def __init__(self, url):
        super().__init__(url)
        spec = url.removeprefix("rclone:")
        name, sep, path = spec.partition(":")
        if not sep:
            name, _, path = spec.partition("/")
        if not name.strip() or name.startswith("-") or any(c in name for c in "/\\\r\n"):
            raise JkeyError("Expected rclone:<remote>[:path]")
        self.root = f"{name}:{path.rstrip('/')}"

    def _key(self, key):
        if safe_remote_key(key) is None:
            raise JkeyError(f"Refusing unexpected rclone object: {key!r}")
        return self.root + ("" if self.root.endswith(":") else "/") + key

    def _run(self, command, *args, missing_ok=False):
        try:
            result = subprocess.run(["rclone", command, *args], capture_output=True, text=True, check=False)
        except FileNotFoundError as e:
            raise JkeyError("rclone is not installed. Install rclone and configure it with 'rclone config'.") from e
        except OSError as e:
            raise JkeyError(f"Cannot start rclone: {e}") from e
        if missing_ok and result.returncode in (3, 4):
            return None
        if result.returncode:
            # rclone logs may contain provider credentials; never echo them.
            raise JkeyError(f"rclone {command} failed (exit {result.returncode}); check the remote with rclone.")
        return result.stdout

    def put(self, local_path, key, progress=None):
        self._run("copyto", "--", os.path.abspath(local_path), self._key(key))
        if progress:
            progress(os.path.getsize(local_path))

    def get(self, key, dest_path, progress=None):
        self._run("copyto", "--", self._key(key), os.path.abspath(dest_path))
        if progress:
            progress(os.path.getsize(dest_path))

    def list_keys(self):
        raw = self._run("lsjson", "--files-only", "--max-depth", "1", "--", self.root, missing_ok=True)
        try:
            return sorted(item["Path"] for item in json.loads(raw or "[]") if not item.get("IsDir"))
        except (ValueError, KeyError, TypeError) as e:
            raise JkeyError("Invalid file listing returned by rclone") from e

    def delete(self, key):
        self._run("deletefile", "--", self._key(key), missing_ok=True)

    def size(self, key):
        raw = self._run("lsjson", "--stat", "--", self._key(key), missing_ok=True)
        try:
            return json.loads(raw)["Size"] if raw else None
        except (ValueError, KeyError, TypeError):
            return None

    def probe(self):
        key = f".probe-{uuid.uuid4().hex}"
        with tempfile.TemporaryDirectory() as tmp:
            src = os.path.join(tmp, "source")
            dest = os.path.join(tmp, "readback")
            with open(src, "wb") as f:
                f.write(b"jkey probe")
            self.put(src, key)
            try:
                self.get(key, dest)
                with open(dest, "rb") as f:
                    if f.read() != b"jkey probe":
                        raise JkeyError("rclone probe read-back mismatch")
            finally:
                self.delete(key)
