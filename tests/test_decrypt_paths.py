"""Standalone decryption paths: prompts, env password, raw payloads, failure modes."""

import base64
import json

import pytest

from jkey.errors import JkeyError
from jkey.pv import core
from jkey.pv.decrypt import decrypt_file


def test_missing_file_raises(vault_dir):
    with pytest.raises(JkeyError, match="File not found"):
        decrypt_file(str(vault_dir / "nope.jkey"))


def test_wrong_env_password_fails_without_prompt(vault_dir, monkeypatch):
    path = str(vault_dir / "x.jkey")
    core.encrypt_file(path, {"totp": {"a": "SECRET"}}, "right")
    monkeypatch.setenv("JKEY_PASS", "wrong")
    with pytest.raises(JkeyError, match="Decryption failed"):
        decrypt_file(path)


def test_native_json_prints_to_stdout(vault_dir, monkeypatch, capsys):
    path = str(vault_dir / "x.jkey")
    core.encrypt_file(path, {"totp": {"a": "SECRET"}}, "pw")
    monkeypatch.setenv("JKEY_PASS", "pw")
    decrypt_file(path)
    assert json.loads(capsys.readouterr().out) == {"totp": {"a": "SECRET"}}


def test_prompts_when_no_env_or_session(vault_dir, monkeypatch, capsys):
    path = str(vault_dir / "x.jkey")
    core.encrypt_file(path, {"totp": {"a": "SECRET"}}, "typed")
    monkeypatch.delenv("JKEY_PASS", raising=False)
    monkeypatch.setattr("getpass.getpass", lambda p="": "typed")
    decrypt_file(path)
    assert json.loads(capsys.readouterr().out) == {"totp": {"a": "SECRET"}}


def test_binary_payload_hints_at_output_file(vault_dir, monkeypatch, capsys):
    path = str(vault_dir / "x.jkey")
    core.encrypt_file(path, {"raw": base64.b64encode(b"\x00\x01binary").decode()}, "pw")
    monkeypatch.setenv("JKEY_PASS", "pw")
    decrypt_file(path)
    assert "binary data" in capsys.readouterr().out
