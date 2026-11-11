import json
import os
from types import SimpleNamespace

import pytest

from jkey.errors import JkeyError
from jkey.pv import core, session_store


def test_password_change_rekeys_qr_and_invalidates_other_terminals(vault, monkeypatch):
    core.save_qr_image("example", b"QR image bytes")
    old = core.read_jkey(core._qr_path("example"))
    monkeypatch.setattr(core, "_terminal_id", lambda: "other-terminal")
    core._save_session("test-password", {}, {}, {})
    other = core._session_file()
    monkeypatch.setattr(core, "_terminal_id", lambda: "current-terminal")
    assert core.change_master_password("new-password")
    assert core.load_qr_image("example") == b"QR image bytes"
    new = core.read_jkey(core._qr_path("example"))
    assert new != old
    assert core._aes().decrypt(new, "test-password") is None
    assert not os.path.exists(other)
    core.lock()
    assert core.unlock_all("new-password")
    assert core.load_qr_image("example") == b"QR image bytes"


def test_rekey_commit_failure_rolls_back_qr_and_all_data(vault, monkeypatch):
    core.save_qr_image("example", b"QR bytes")
    paths = [core.TOTP_FILE, core.PASSWORDS_FILE, core.RECOVERY_FILE, core._qr_path("example")]
    before = {p: open(p, "rb").read() for p in paths}
    original = os.replace

    def fail(src, dest):
        # QR is committed after the three vault JSON files.
        if str(src).endswith("new-3"):
            raise OSError("QR commit failed")
        return original(src, dest)

    monkeypatch.setattr(os, "replace", fail)
    with pytest.raises(JkeyError, match="failed to re-encrypt"):
        core.change_master_password("new-password")
    assert {p: open(p, "rb").read() for p in paths} == before
    assert core.get_session_password() == "test-password"
    assert core.load_qr_image("example") == b"QR bytes"


def test_undecipherable_qr_aborts_rekey_without_changing_any_file(vault):
    core.save_qr_image("example", b"QR bytes")
    core.encrypt_file(core._qr_path("example"), {"raw": "data"}, "different-password")
    before = open(core.TOTP_FILE, "rb").read()
    with pytest.raises(JkeyError, match="Cannot decrypt QR"):
        core.change_master_password("new-password")
    assert open(core.TOTP_FILE, "rb").read() == before
    assert core.verify_password("test-password")


def test_session_disk_ticket_contains_no_password_or_decrypted_data(vault, native_session_store):
    core.save_passwords({"secret-account": "secret-value"})
    raw = open(core._session_file()).read()
    assert "test-password" not in raw
    assert "secret-account" not in raw
    assert "secret-value" not in raw
    assert set(json.loads(raw)) == {"sv", "expires", "vault_fp"}
    assert native_session_store[core._session_file()] == "test-password"


def test_unavailable_secure_store_does_not_write_plaintext_fallback(vault_dir, monkeypatch, capsys):
    monkeypatch.setattr(session_store, "save", lambda *_: False)
    core.set_unlocked("secret-password", {"secret": "value"}, {}, {})
    assert core.is_unlocked()
    assert not os.path.exists(core._session_file())
    assert not core.has_session()
    assert "new commands require authentication" in capsys.readouterr().err
    assert not any(p.suffix == ".json" for p in vault_dir.rglob("*"))


def test_first_use_removes_legacy_plaintext_tickets_for_all_terminals(vault_dir):
    core.ensure_dir()
    os.makedirs(core.SESSION_DIR, exist_ok=True)
    for tid in ("old-A", "old-B"):
        with open(core._session_file(tid), "w") as f:
            json.dump({"sv": 3, "password": "old-password"}, f)
    with open(core._LEGACY_SESSION_FILE, "w") as f:
        f.write("old-password")
    with open(core._LEGACY_SESSION_FILE + ".tmp", "w") as f:
        f.write("old-password")
    leftover = core._session_file("old-C") + ".tmp"
    with open(leftover, "w") as f:
        f.write("old-password")
    core.ensure_dir()
    assert not os.path.exists(leftover)
    assert not os.path.exists(core._LEGACY_SESSION_FILE + ".tmp")
    assert not list(core._iter_session_files())
    assert not os.path.exists(core._LEGACY_SESSION_FILE)


def test_expired_ticket_removes_keyring_password(vault, monkeypatch, native_session_store):
    path = core._session_file()
    monkeypatch.setattr(core.time, "time", lambda: float("inf"))
    assert not core.has_session()
    assert path not in native_session_store
    assert not os.path.exists(path)


def test_native_backend_filter_rejects_plaintext_and_fail_backends(monkeypatch):
    import keyring

    class Plaintext:
        pass

    Plaintext.__module__ = "keyrings.alt.file"
    monkeypatch.setattr(keyring, "get_keyring", lambda: Plaintext())
    assert session_store._backend() is None


def test_native_backend_filter_selects_native_from_chainer(monkeypatch):
    import keyring

    class Native:
        pass

    Native.__module__ = "keyring.backends.SecretService"
    native = Native()
    chain = SimpleNamespace(backends=[object(), native])
    monkeypatch.setattr(keyring, "get_keyring", lambda: chain)
    assert session_store._backend() is native
