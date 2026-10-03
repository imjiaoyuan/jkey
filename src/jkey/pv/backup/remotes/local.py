"""Local filesystem backend — NAS mounts, USB drives, or any mounted path. Zero dependencies."""

import os
import shutil
import time

from jkey.errors import JkeyError
from jkey.pv.backup.remotes.base import Remote, safe_remote_key

_INVALID_FS_CHARS = '<>:"/\\|?*'


class LocalRemote(Remote):
    def __init__(self, url: str, endpoint: str | None = None, region: str | None = None):
        super().__init__(url, endpoint, region)
        self.root = url.removeprefix("file://")
        if not self.root:
            raise JkeyError(f"Empty local backup path: {url!r}")

    def _path(self, key: str) -> str:
        if safe_remote_key(key) is None:
            raise JkeyError(f"Refusing to touch unexpected remote object: {key!r}")
        safe = key
        for ch in _INVALID_FS_CHARS:
            safe = safe.replace(ch, "_")
        return os.path.join(self.root, safe)

    def put(self, local_path: str, key: str) -> None:
        dest = self._path(key)
        try:
            os.makedirs(os.path.dirname(dest), mode=0o700, exist_ok=True)
            shutil.copyfile(local_path, dest)
            os.chmod(dest, 0o600)
        except OSError as e:
            raise JkeyError(f"backup write failed ({self.url}/{key}): {e}") from e

    def get(self, key: str, dest_path: str) -> None:
        src = self._path(key)
        try:
            with open(src, "rb") as fsrc, open(dest_path, "wb") as fdst:
                fdst.write(fsrc.read())
        except FileNotFoundError as e:
            raise JkeyError(f"snapshot not found on remote: {key}") from e
        except OSError as e:
            raise JkeyError(f"backup read failed ({self.url}/{key}): {e}") from e

    def list_keys(self) -> list[str]:
        if not os.path.isdir(self.root):
            return []
        try:
            return sorted(os.listdir(self.root))
        except OSError as e:
            raise JkeyError(f"cannot list backup dir {self.root}: {e}") from e

    def delete(self, key: str) -> None:
        try:
            os.unlink(self._path(key))
        except FileNotFoundError:
            return
        except OSError as e:
            raise JkeyError(f"cannot delete {self.url}/{key}: {e}") from e

    def probe(self) -> None:
        """Write, read back, verify, delete a probe file — proves the target is usable."""
        key = f"{time.strftime('%Y%m%d-%H%M%S')}.sha256"  # manifest-style name passes the key whitelist
        probe_path = self._path(key)
        try:
            os.makedirs(self.root, mode=0o700, exist_ok=True)
            payload = b"jkey probe"
            with open(probe_path, "wb") as f:
                f.write(payload)
            with open(probe_path, "rb") as f:
                if f.read() != payload:
                    raise JkeyError("probe read-back mismatch")
        except OSError as e:
            raise JkeyError(f"backup target not writable ({self.root}): {e}") from e
        finally:
            try:
                os.unlink(probe_path)
            except OSError:
                pass
