"""Tests for the encrypt.py / decrypt.py command-line entry points."""

import pytest

import decrypt
import encrypt
import utils

PASSWORD = "cli-password"


@pytest.fixture(autouse=True)
def fast_kdf(monkeypatch):
    monkeypatch.setattr(utils, "PBKDF2_ITERATIONS", 1_000)


def test_cli_round_trip(tmp_path, monkeypatch, capsys):
    source = tmp_path / "notes.txt"
    source.write_text("hello from the CLI")

    monkeypatch.setattr(encrypt.getpass, "getpass", lambda prompt="": PASSWORD)
    encrypt.encrypt(str(source))
    assert "[OK] File encrypted successfully" in capsys.readouterr().out

    monkeypatch.setattr(decrypt.getpass, "getpass", lambda prompt="": PASSWORD)
    decrypt.decrypt(str(tmp_path / "notes.txt.enc"))
    assert "[OK] File decrypted successfully" in capsys.readouterr().out

    assert (tmp_path / "notes.txt.dec").read_text() == "hello from the CLI"


def test_cli_wrong_password_exits_with_error(tmp_path, monkeypatch, capsys):
    source = tmp_path / "notes.txt"
    source.write_text("hello")
    monkeypatch.setattr(encrypt.getpass, "getpass", lambda prompt="": PASSWORD)
    encrypt.encrypt(str(source))

    monkeypatch.setattr(decrypt.getpass, "getpass", lambda prompt="": "wrong")
    with pytest.raises(SystemExit) as exc_info:
        decrypt.decrypt(str(tmp_path / "notes.txt.enc"))
    assert exc_info.value.code == 1
    assert "[ERROR]" in capsys.readouterr().err
