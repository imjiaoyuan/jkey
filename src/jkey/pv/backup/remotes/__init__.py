"""Scheme-based remote construction. Adding a backend = implement Remote + a branch here.

Imports stay lazy per-scheme: the S3 module imports boto3 only inside its client accessor,
so `open_remote` on a local remote never pays the (nonexistent) boto3 import and vice versa.
"""

from urllib.parse import urlparse

from jkey.errors import JkeyError
from jkey.pv.backup.remotes.base import Remote


def open_remote(cfg: dict) -> Remote:
    """Build a Remote from a remotes.json entry: {'url': ..., 'endpoint': ..., ...}."""
    url = cfg.get("url", "")
    scheme = urlparse(url).scheme.lower()
    # Windows drive letters ("C:\..." or "C:/...") parse as a scheme — still a local path.
    if len(scheme) == 1 and len(url) > 2 and url[1] == ":" and url[2] in ("\\", "/"):
        scheme = ""

    if scheme == "s3":
        from jkey.pv.backup.remotes.s3 import S3Remote

        return S3Remote(
            url,
            cfg.get("endpoint"),
            cfg.get("region"),
            cfg.get("access_key"),
            cfg.get("secret_key"),
        )

    # Plain paths and file:// mean the local filesystem (NAS mount, USB drive, ...).
    if scheme in ("", "file"):
        from jkey.pv.backup.remotes.local import LocalRemote

        return LocalRemote(url, cfg.get("endpoint"), cfg.get("region"))

    raise JkeyError(f"Unsupported backup URL scheme: {url!r} (supported: local path, s3://bucket/prefix)")
