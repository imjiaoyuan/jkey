"""Unit coverage for the native credential store adapter (bypasses the autouse session fake)."""

import pytest

from jkey.pv import session_store

real_save = session_store.save
real_load = session_store.load
real_delete = session_store.delete


class FakeBackend:
    def __init__(self, fail=False):
        self.store = {}
        self.fail = fail

    def set_password(self, service, account, password):
        if self.fail:
            raise RuntimeError("keyring daemon down")
        self.store[account] = password

    def get_password(self, service, account):
        if self.fail:
            raise RuntimeError("keyring daemon down")
        return self.store.get(account)

    def delete_password(self, service, account):
        if self.fail:
            raise RuntimeError("keyring daemon down")
        self.store.pop(account, None)


def _real_functions(mp):
    mp.setattr(session_store, "save", real_save)
    mp.setattr(session_store, "load", real_load)
    mp.setattr(session_store, "delete", real_delete)


def test_roundtrip():
    mp = pytest.MonkeyPatch()
    backend = FakeBackend()
    mp.setattr(session_store, "_backend", lambda: backend)
    _real_functions(mp)
    assert session_store.save("v", "pw") is True
    assert session_store.load("v") == "pw"
    session_store.delete("v")
    assert session_store.load("v") is None
    mp.undo()


def test_absent_backend_is_silent(capsys):
    mp = pytest.MonkeyPatch()
    mp.setattr(session_store, "_backend", lambda: None)
    _real_functions(mp)
    assert session_store.save("v", "pw") is False
    assert session_store.load("v") is None
    session_store.delete("v")
    assert capsys.readouterr().err == ""
    mp.undo()


def test_backend_failure_warns_once(capsys):
    mp = pytest.MonkeyPatch()
    mp.setattr(session_store, "_backend", lambda: FakeBackend(fail=True))
    mp.setattr(session_store, "_warned", False)
    _real_functions(mp)
    assert session_store.save("v", "pw") is False
    assert session_store.load("v") is None
    err = capsys.readouterr().err
    assert "credential store rejected" in err
    assert err.count("\n") == 1
    session_store.delete("v")
    assert capsys.readouterr().err == ""
    mp.undo()


def test_keyring_probe_failure_means_no_backend(monkeypatch):
    import keyring

    def boom():
        raise RuntimeError("keyring exploded")

    monkeypatch.setattr(keyring, "get_keyring", boom)
    assert session_store._backend() is None
