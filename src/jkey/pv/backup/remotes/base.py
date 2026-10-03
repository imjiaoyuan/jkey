"""Shared pieces for remote backends: key validation and the abstract Remote interface."""

import re
from abc import ABC, abstractmethod

_SNAPSHOT_RE = re.compile(r"^\d{8}-\d{6}\.tar\.gz$")
_MANIFEST_RE = re.compile(r"^\d{8}-\d{6}\.sha256$")
_LATEST = "LATEST"


def valid_snapshot(name: str) -> bool:
    """A snapshot name like 20250611-143022.tar.gz (also guards against path traversal)."""
    return bool(_SNAPSHOT_RE.match(name))


def snapshot_stamp(name: str) -> str:
    """'20250611-143022' from '20250611-143022.tar.gz'; raises ValueError otherwise."""
    if not valid_snapshot(name):
        raise ValueError(f"not a snapshot name: {name!r}")
    return name[: -len(".tar.gz")]


def safe_remote_key(name: str) -> str | None:
    """Objects this feature may touch on a remote: snapshots, manifests, LATEST.

    Returns None for anything else — callers must treat None as 'refuse to touch'.
    """
    if name == _LATEST or _SNAPSHOT_RE.match(name) or _MANIFEST_RE.match(name):
        return name
    return None


class Remote(ABC):
    """Minimal storage interface implemented by every backend."""

    def __init__(self, url: str, endpoint: str | None = None, region: str | None = None):
        self.url = url
        self.endpoint = endpoint
        self.region = region

    @abstractmethod
    def put(self, local_path: str, key: str) -> None:
        """Upload local file as key."""

    @abstractmethod
    def get(self, key: str, dest_path: str) -> None:
        """Download key to dest_path."""

    @abstractmethod
    def list_keys(self) -> list[str]:
        """List object names under the remote root."""

    @abstractmethod
    def delete(self, key: str) -> None:
        """Delete key."""

    @abstractmethod
    def probe(self) -> None:
        """Connectivity test: write, read back, verify, delete a probe object."""
