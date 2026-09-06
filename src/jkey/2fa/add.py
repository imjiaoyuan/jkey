import os
import sys
from urllib.parse import parse_qs, unquote, urlparse

from jkey.errors import JkeyError
from jkey.pv.core import load_totp, save_qr_image, save_totp

from .core import validate_b32_secret

try:
    import cv2
except ImportError:
    cv2 = None


def _resize_if_large(img, max_size=1000):
    h, w = img.shape[:2]
    if max(h, w) > max_size:
        scale = max_size / max(h, w)
        new_w, new_h = int(w * scale), int(h * scale)
        return cv2.resize(img, (new_w, new_h), interpolation=cv2.INTER_LINEAR)
    return img


def scan_and_add(image_path: str) -> None:
    if cv2 is None:
        raise JkeyError(
            "opencv-python-headless is required for QR scanning. Install with: pip install opencv-python-headless"
        )
    if not os.path.exists(image_path):
        raise JkeyError(f"File not found: {image_path}")

    img = cv2.imread(image_path)
    if img is None:
        raise JkeyError(f"Could not read image: {image_path}")

    small = _resize_if_large(img)
    detector = cv2.QRCodeDetector()
    decoded, _, _ = detector.detectAndDecode(small)
    if not decoded:
        raise JkeyError("No QR code found in the image.")

    parsed = urlparse(decoded)
    if parsed.scheme != "otpauth":
        raise JkeyError(f"Not a valid otpauth:// URL: {decoded}")

    params = parse_qs(parsed.query)
    secret = params.get("secret", [None])[0]
    if not secret:
        raise JkeyError("No secret found in QR code.")
    if not validate_b32_secret(secret):
        raise JkeyError(f"Invalid base32 secret in QR code: {secret!r}")

    path = unquote(parsed.path).lstrip("/")
    issuer = params.get("issuer", [None])[0]

    if issuer and ":" not in path:
        name = f"{issuer}:{path}"
    else:
        name = path

    if not name:
        name = issuer or "unknown"

    data = load_totp()
    if name in data:
        try:
            response = input(f"'{name}' already exists. Overwrite? (y/N): ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print()
            raise JkeyError("Import cancelled.")
        if response != "y":
            raise JkeyError("Import cancelled.")
    data[name] = secret
    save_totp(data)
    print(f"Added 2FA account: {name}")

    try:
        save_qr_image(name, cv2.imencode(".jpg", small)[1].tobytes())
    except (cv2.error, OSError):
        print(f"Warning: failed to save encrypted QR backup for '{name}'", file=sys.stderr)
