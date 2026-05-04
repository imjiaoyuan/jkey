import importlib
import os
from urllib.parse import urlparse, parse_qs, unquote

import cv2

from jkey.pv.core import load_totp, save_totp, save_qr_image

_core = importlib.import_module("jkey.2fa.core")
_import_recovery_file = _core._import_recovery_file


def scan_and_add(image_path: str, recovery_path: str | None = None):
    if not os.path.exists(image_path):
        print(f"Error: File not found: {image_path}")
        return

    img = cv2.imread(image_path)
    if img is None:
        print(f"Error: Could not read image: {image_path}")
        return

    detector = cv2.QRCodeDetector()
    data, _, _ = detector.detectAndDecode(img)
    if not data:
        print("Error: No QR code found in the image.")
        return

    parsed = urlparse(data)
    if parsed.scheme != "otpauth":
        print(f"Error: Not a valid otpauth:// URL: {data}")
        return

    params = parse_qs(parsed.query)
    secret = params.get("secret", [None])[0]
    if not secret:
        print("Error: No secret found in QR code.")
        return

    path = unquote(parsed.path).lstrip("/")
    issuer = params.get("issuer", [None])[0]

    if issuer and path.startswith(issuer + ":"):
        name = path[len(issuer) + 1:]
    elif issuer and ":" in path:
        name = path
    else:
        name = path

    if not name:
        name = issuer or "unknown"

    data = load_totp()
    if data is None:
        return
    data[name] = secret
    save_totp(data)
    print(f"Added 2FA account: {name}")

    try:
        save_qr_image(name, cv2.imencode(".jpg", img)[1].tobytes())
    except Exception:
        pass

    _import_recovery_file(name, recovery_path)
