import os
import sys
from urllib.parse import parse_qs, unquote, urlparse

import cv2

from jkey.pv.core import load_totp, save_qr_image, save_totp


def _resize_if_large(img, max_size=1000):
    h, w = img.shape[:2]
    if max(h, w) > max_size:
        scale = max_size / max(h, w)
        new_w, new_h = int(w * scale), int(h * scale)
        return cv2.resize(img, (new_w, new_h), interpolation=cv2.INTER_LINEAR)
    return img


def scan_and_add(image_path: str):
    if not os.path.exists(image_path):
        print(f"Error: File not found: {image_path}")
        return

    img = cv2.imread(image_path)
    if img is None:
        print(f"Error: Could not read image: {image_path}")
        return

    small = _resize_if_large(img)
    detector = cv2.QRCodeDetector()
    data, _, _ = detector.detectAndDecode(small)
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

    if issuer and ":" in path:
        name = path
    elif issuer:
        name = f"{issuer}:{path}"
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
        resized = _resize_if_large(img, max_size=1000)
        save_qr_image(name, cv2.imencode(".jpg", resized)[1].tobytes())
    except Exception:
        print(f"Warning: failed to save encrypted QR backup for '{name}'", file=sys.stderr)
