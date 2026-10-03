"""S3 backend (AWS S3 and S3-compatible: OSS, COS, MinIO, R2, B2). boto3 is a lazy extra."""

from jkey.errors import JkeyError
from jkey.pv.backup.remotes.base import Remote, safe_remote_key

_PROBE_BODY = b"jkey probe"


def _client_error_reason(e) -> str | None:
    """Map botocore error codes to actionable hints."""
    code = getattr(e, "response", {}).get("Error", {}).get("Code", "") if hasattr(e, "response") else ""
    return {
        "AccessDenied": "access denied — the credentials need PutObject/GetObject/DeleteObject/ListObjectsV2",
        "NoSuchBucket": "bucket does not exist",
        "404": "bucket does not exist",
        "InvalidAccessKeyId": "access key is invalid",
        "SignatureDoesNotMatch": "secret key is invalid",
        "RequestTimeTooSkewed": "clock skew detected — sync system time",
    }.get(code)


def _wrap_s3_error(action: str, url: str, e) -> JkeyError:
    import re

    detail = getattr(e, "response", {}).get("Error", {}).get("Message", "") if hasattr(e, "response") else ""
    hint = _client_error_reason(e)
    msg = f"s3 {action} failed ({url}): {type(e).__name__}"
    if detail:
        msg += f": {detail}"
    if hint:
        msg += f" — {hint}"
    # botocore can embed credentials in error strings; drop key=value forms and AKID-looking tokens.
    msg = re.sub(r"(?i)(access[-_]?key|secret[-_]?key|token)[= ]+\S+", r"\1=***", msg)
    msg = re.sub(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b", "***", msg)
    return JkeyError(msg)


class S3Remote(Remote):
    def __init__(
        self,
        url: str,
        endpoint: str | None = None,
        region: str | None = None,
        access_key: str | None = None,
        secret_key: str | None = None,
    ):
        super().__init__(url, endpoint, region)
        from urllib.parse import urlparse

        parsed = urlparse(url)
        self.bucket = parsed.netloc
        self.prefix = parsed.path.strip("/")
        if not self.bucket:
            raise JkeyError(f"Invalid S3 URL (expected s3://bucket/prefix): {url!r}")
        self.access_key = access_key
        self.secret_key = secret_key
        self._client = None

    def _s3(self):
        if self._client is not None:
            return self._client
        try:
            import boto3
        except ImportError as e:
            raise JkeyError("S3 support not installed. Run: pip install jkey[s3]") from e
        kwargs = {}
        if self.region:
            kwargs["region_name"] = self.region
        if self.endpoint:
            kwargs["endpoint_url"] = self.endpoint
        if self.access_key:
            kwargs["aws_access_key_id"] = self.access_key
            kwargs["aws_secret_access_key"] = self.secret_key
        try:
            self._client = boto3.client("s3", **kwargs)
        except Exception as e:
            raise _wrap_s3_error("client init", self.url, e) from e
        return self._client

    def _key(self, name: str) -> str:
        if safe_remote_key(name) is None:
            raise JkeyError(f"Refusing to touch unexpected remote object: {name!r}")
        return f"{self.prefix}/{name}" if self.prefix else name

    def put(self, local_path: str, key: str) -> None:
        try:
            self._s3().upload_file(local_path, self.bucket, self._key(key))
        except Exception as e:
            raise _wrap_s3_error("upload", self.url, e) from e

    def get(self, key: str, dest_path: str) -> None:
        try:
            self._s3().download_file(self.bucket, self._key(key), dest_path)
        except Exception as e:
            raise _wrap_s3_error("download", self.url, e) from e

    def list_keys(self) -> list[str]:
        try:
            resp = self._s3().list_objects_v2(Bucket=self.bucket, Prefix=f"{self.prefix}/" if self.prefix else "")
        except Exception as e:
            raise _wrap_s3_error("list", self.url, e) from e
        names = []
        plen = len(self.prefix) + 1 if self.prefix else 0
        for obj in resp.get("Contents", []):
            name = obj["Key"][plen:]
            if "/" not in name:  # ignore objects nested deeper than the root
                names.append(name)
        return sorted(names)

    def delete(self, key: str) -> None:
        try:
            self._s3().delete_object(Bucket=self.bucket, Key=self._key(key))
        except Exception as e:
            raise _wrap_s3_error("delete", self.url, e) from e

    def probe(self) -> None:
        import time

        key = self._key(f"{time.strftime('%Y%m%d-%H%M%S')}.sha256")  # manifest-style probe name
        s3 = self._s3()
        try:
            import io

            s3.upload_fileobj(io.BytesIO(_PROBE_BODY), self.bucket, key)
        except Exception as e:
            raise _wrap_s3_error("probe write", self.url, e) from e
        try:
            resp = s3.get_object(Bucket=self.bucket, Key=key)
            if resp["Body"].read() != _PROBE_BODY:
                raise JkeyError("probe read-back mismatch")
        except JkeyError:
            raise
        except Exception as e:
            raise _wrap_s3_error("probe read", self.url, e) from e
        finally:
            try:
                s3.delete_object(Bucket=self.bucket, Key=key)
            except Exception:
                pass
