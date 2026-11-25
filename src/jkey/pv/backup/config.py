"""Backup remote configuration: remotes.json in the vault config directory."""

import json
import os
import textwrap
from urllib.parse import urlparse

from jkey.errors import JkeyError
from jkey.pv import core


def _remotes_file() -> str:
    """Computed on call so tests that patch core.CONFIG_DIR never see a stale path."""
    return os.path.join(core.CONFIG_DIR, "remotes.json")


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


def urlparse_scheme(url: str) -> str:
    scheme = urlparse(url).scheme.lower()
    # Windows drive letters ("C:\..." or "C:/...") parse as a single-letter scheme — a local path.
    if len(scheme) == 1 and len(url) > 2 and url[1] == ":" and url[2] in ("\\", "/"):
        return ""
    return scheme
