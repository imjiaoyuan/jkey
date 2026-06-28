import binascii
import importlib
import json


class _FakeImage:
    shape = (100, 100, 3)


class _FakeDetector:
    def __init__(self, data: str):
        self._data = data

    def detectAndDecode(self, _img):
        return self._data, None, None


class _FakeEncoded:
    def tobytes(self):
        return b"jpg-bytes"


class Test2faAddPaths:
    def test_scan_invalid_scheme(self, monkeypatch, capsys):
        mod = importlib.import_module("jkey.2fa.add")

        monkeypatch.setattr(mod.os.path, "exists", lambda _p: True)
        monkeypatch.setattr(mod.cv2, "imread", lambda _p: _FakeImage())
        monkeypatch.setattr(mod.cv2, "QRCodeDetector", lambda: _FakeDetector("https://example.com"))

        mod.scan_and_add("/tmp/qr.png")
        captured = capsys.readouterr()
        assert "Not a valid otpauth://" in captured.out

    def test_scan_success_warns_when_qr_backup_fails(self, monkeypatch, capsys):
        mod = importlib.import_module("jkey.2fa.add")
        stored = {}

        monkeypatch.setattr(mod.os.path, "exists", lambda _p: True)
        monkeypatch.setattr(mod.cv2, "imread", lambda _p: _FakeImage())
        monkeypatch.setattr(
            mod.cv2,
            "QRCodeDetector",
            lambda: _FakeDetector("otpauth://totp/account?secret=JBSWY3DPEHPK3PXP&issuer=GitHub"),
        )
        monkeypatch.setattr(mod, "load_totp", lambda: {})
        monkeypatch.setattr(mod, "save_totp", lambda data: stored.update(data))
        monkeypatch.setattr(mod.cv2, "imencode", lambda _ext, _img: (True, _FakeEncoded()))
        monkeypatch.setattr(mod, "save_qr_image", lambda _name, _data: (_ for _ in ()).throw(OSError("disk full")))

        mod.scan_and_add("/tmp/qr.png")
        captured = capsys.readouterr()
        assert "Added 2FA account: GitHub:account" in captured.out
        assert "GitHub:account" in stored
        assert "failed to save encrypted QR backup" in captured.err


class TestListCommands:
    def test_2fa_list_error_path(self, monkeypatch, capsys):
        mod = importlib.import_module("jkey.2fa.ls")

        monkeypatch.setattr(mod, "load_totp", lambda: {"acc": "bad-secret"})
        monkeypatch.setattr(mod, "totp", lambda _secret: (_ for _ in ()).throw(binascii.Error("bad base32")))

        result = mod.list_accounts()
        assert len(result) == 1
        assert result[0][0] == "acc"
        assert "Error" in result[0][1]

    def test_pm_list_keyword_no_match(self, monkeypatch, capsys):
        mod = importlib.import_module("jkey.pm.ls")

        monkeypatch.setattr(mod, "load_passwords", lambda: {"GitHub": "pw"})
        result = mod.list_passwords("gitlab")
        assert result == {}


class TestExportPaths:
    def test_export_uses_env_password_without_prompt(self, monkeypatch, capsys):
        mod = importlib.import_module("jkey.pv.export")

        monkeypatch.setattr(mod, "_ensure_unlocked", lambda: True)
        monkeypatch.setattr(mod, "_password_from_env", lambda: "from-env")
        monkeypatch.setattr(mod, "verify_password", lambda pw: pw == "from-env")
        monkeypatch.setattr(mod, "load_totp", lambda: {"github": "JBSWY3DPEHPK3PXP"})
        monkeypatch.setattr(mod.getpass, "getpass", lambda _p: (_ for _ in ()).throw(AssertionError("prompted")))

        args = type("Args", (), {"type": "totp", "output": None})
        mod.cmd_export(args)
        captured = capsys.readouterr()
        assert "\"github\"" in captured.out

    def test_export_qr_writes_images(self, monkeypatch, tmp_path, capsys):
        mod = importlib.import_module("jkey.pv.export")

        monkeypatch.setattr(mod, "_ensure_unlocked", lambda: True)
        monkeypatch.setattr(mod, "_password_from_env", lambda: "pw")
        monkeypatch.setattr(mod, "verify_password", lambda _pw: True)
        monkeypatch.setattr(mod, "list_qr_images", lambda: ["acc1"])
        monkeypatch.setattr(mod, "load_qr_image", lambda _name: b"image-bytes")

        args = type("Args", (), {"type": "qr", "output": str(tmp_path)})
        mod.cmd_export(args)
        captured = capsys.readouterr()
        assert "Exported 1 QR images" in captured.out
        assert (tmp_path / "acc1.jpg").read_bytes() == b"image-bytes"

    def test_export_all_writes_combined_outputs(self, monkeypatch, tmp_path):
        mod = importlib.import_module("jkey.pv.export")

        monkeypatch.setattr(mod, "_ensure_unlocked", lambda: True)
        monkeypatch.setattr(mod, "_password_from_env", lambda: "pw")
        monkeypatch.setattr(mod, "verify_password", lambda _pw: True)
        monkeypatch.setattr(mod, "load_totp", lambda: {"github": "JBSWY3DPEHPK3PXP"})
        monkeypatch.setattr(mod, "load_passwords", lambda: {"site": "pass"})
        monkeypatch.setattr(mod, "load_recovery", lambda: {"github": ["rc1"]})
        monkeypatch.setattr(mod, "list_qr_images", lambda: ["github"])
        monkeypatch.setattr(mod, "load_qr_image", lambda _name: b"img")

        args = type("Args", (), {"type": "all", "output": str(tmp_path)})
        mod.cmd_export(args)

        assert json.loads((tmp_path / "totp.json").read_text())["github"] == "JBSWY3DPEHPK3PXP"
        assert "name,password" in (tmp_path / "passwords.csv").read_text()
        assert "Account: github" in (tmp_path / "recovery.txt").read_text()
        assert (tmp_path / "qr" / "github.jpg").read_bytes() == b"img"
