import os
import shutil

import pytest

from jkey import aes


@pytest.fixture
def vault_dir(tmp_path, monkeypatch):
    """Set up a temporary vault directory and monkeypatch all paths."""
    import jkey.pv.core as core

    d = str(tmp_path)
    monkeypatch.setattr(core, "CONFIG_DIR", d)
    monkeypatch.setattr(core, "TOTP_FILE", os.path.join(d, "totp.jkey"))
    monkeypatch.setattr(core, "PASSWORDS_FILE", os.path.join(d, "passwords.jkey"))
    monkeypatch.setattr(core, "RECOVERY_FILE", os.path.join(d, "recovery.jkey"))
    monkeypatch.setattr(core, "QR_DIR", os.path.join(d, "qr"))
    monkeypatch.setattr(core, "SESSION_FILE", os.path.join(d, ".session"))
    yield tmp_path
    # Reset module globals
    core._session_password = None
    core._totp_cache = None
    core._passwords_cache = None
    core._recovery_cache = None


@pytest.fixture
def vault(vault_dir):
    """Return an initialized and unlocked vault for testing."""
    import jkey.pv.core as core

    pw = "test-password"
    core._ensure_dir()
    core._encrypt_file(core.TOTP_FILE, {}, pw)
    core._encrypt_file(core.PASSWORDS_FILE, {}, pw)
    core._encrypt_file(core.RECOVERY_FILE, {}, pw)
    core._unlock_all(pw)
    return core


@pytest.fixture
def mock_getpass(monkeypatch):
    """Mock getpass.getpass to return a fixed password."""

    def _mock(prompt="", pw="test-password"):
        monkeypatch.setattr("getpass.getpass", lambda p="": pw)
        return pw

    return _mock
