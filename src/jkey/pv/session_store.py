"""Only native OS credential stores may hold session passwords. No file fallback."""

import hashlib
import os
import sys

_SERVICE = "jkey.session.v4"
_ALLOWED = {"keyring.backends.SecretService", "keyring.backends.macOS", "keyring.backends.Windows"}
_warned = False


def _warn_once() -> None:
    global _warned
    if not _warned:
        _warned = True
        print(
            "jkey: OS credential store rejected a session password; every new command will ask for it again.",
            file=sys.stderr,
        )


def _backend():
    try:
        import keyring

        backend = keyring.get_keyring()
        candidates = getattr(backend, "backends", [backend])
        for candidate in candidates:
            if type(candidate).__module__ in _ALLOWED:
                return candidate
    except Exception:
        pass
    return None


def _account(path):
    return hashlib.sha256(os.path.abspath(path).encode()).hexdigest()


def save(path, password):
    backend = _backend()
    if backend is None:
        return False
    try:
        backend.set_password(_SERVICE, _account(path), password)
        return True
    except Exception:
        _warn_once()
        return False


def load(path):
    backend = _backend()
    if backend is None:
        return None
    try:
        return backend.get_password(_SERVICE, _account(path))
    except Exception:
        _warn_once()
        return None


def delete(path):
    backend = _backend()
    if backend is not None:
        try:
            backend.delete_password(_SERVICE, _account(path))
        except Exception:
            _warn_once()
