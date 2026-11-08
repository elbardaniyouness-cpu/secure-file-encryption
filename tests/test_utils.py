"""Tests for the core encryption/decryption logic in utils.py."""

import pytest

import utils
from utils import (
    IV_SIZE,
    SALT_SIZE,
    TAG_SIZE,
    EncryptionError,
    decrypt_file,
    encrypt_file,
)

PASSWORD = "correct horse battery staple"
HEADER_SIZE = SALT_SIZE + IV_SIZE + TAG_SIZE
DEFAULT_ITERATIONS = utils.PBKDF2_ITERATIONS  # captured before any patching


@pytest.fixture(autouse=True)
def fast_kdf(monkeypatch):
    """Use fewer PBKDF2 iterations so the suite runs in seconds.

    Production code keeps 600,000 iterations; see test_default_iterations.
    """
    monkeypatch.setattr(utils, "PBKDF2_ITERATIONS", 1_000)


@pytest.fixture
def sample_file(tmp_path):
    path = tmp_path / "secret.txt"
    path.write_bytes(b"Top secret: the exit exam is on 20 January.\n")
    return path


def test_default_iterations_meet_owasp_recommendation():
    assert DEFAULT_ITERATIONS >= 600_000


def test_round_trip_text(sample_file):
    original = sample_file.read_bytes()
    encrypted = encrypt_file(sample_file, PASSWORD)
    decrypted = decrypt_file(encrypted, PASSWORD)
    assert decrypted.read_bytes() == original


@pytest.mark.parametrize("size", [0, 1, 15, 16, 17, 4096, 100_003])
def test_round_trip_binary_of_various_sizes(tmp_path, size):
    path = tmp_path / "data.bin"
    data = bytes(i % 256 for i in range(size))
    path.write_bytes(data)
    decrypted = decrypt_file(encrypt_file(path, PASSWORD), PASSWORD)
    assert decrypted.read_bytes() == data


def test_output_file_names(sample_file):
    encrypted = encrypt_file(sample_file, PASSWORD)
    assert encrypted.name == "secret.txt.enc"
    decrypted = decrypt_file(encrypted, PASSWORD)
    assert decrypted.name == "secret.txt.dec"


def test_file_format_layout(sample_file):
    plaintext_len = len(sample_file.read_bytes())
    encrypted = encrypt_file(sample_file, PASSWORD).read_bytes()
    padded_len = (plaintext_len // 16 + 1) * 16  # PKCS7 always adds padding
    assert len(encrypted) == HEADER_SIZE + padded_len


def test_ciphertext_does_not_contain_plaintext(sample_file):
    encrypted = encrypt_file(sample_file, PASSWORD).read_bytes()
    assert b"Top secret" not in encrypted


def test_same_input_encrypts_differently_each_time(sample_file):
    first = encrypt_file(sample_file, PASSWORD).read_bytes()
    second = encrypt_file(sample_file, PASSWORD).read_bytes()
    assert first[:SALT_SIZE] != second[:SALT_SIZE]  # fresh random salt
    assert first != second


def test_wrong_password_is_rejected(sample_file):
    encrypted = encrypt_file(sample_file, PASSWORD)
    with pytest.raises(EncryptionError, match="Integrity check failed"):
        decrypt_file(encrypted, "wrong password")


@pytest.mark.parametrize(
    "offset",
    [0, SALT_SIZE, SALT_SIZE + IV_SIZE, HEADER_SIZE, -1],
    ids=["salt", "iv", "tag", "ciphertext-start", "ciphertext-end"],
)
def test_any_tampered_byte_is_detected(sample_file, offset):
    encrypted = encrypt_file(sample_file, PASSWORD)
    data = bytearray(encrypted.read_bytes())
    data[offset] ^= 0x01
    encrypted.write_bytes(bytes(data))
    with pytest.raises(EncryptionError):
        decrypt_file(encrypted, PASSWORD)


def test_failed_decryption_writes_no_output(sample_file):
    encrypted = encrypt_file(sample_file, PASSWORD)
    with pytest.raises(EncryptionError):
        decrypt_file(encrypted, "wrong password")
    assert not (sample_file.parent / "secret.txt.dec").exists()


def test_truncated_file_is_rejected(tmp_path):
    path = tmp_path / "short.enc"
    path.write_bytes(b"\x00" * (HEADER_SIZE + 15))
    with pytest.raises(EncryptionError, match="too short"):
        decrypt_file(path, PASSWORD)


def test_empty_password_is_rejected(sample_file):
    with pytest.raises(ValueError, match="must not be empty"):
        encrypt_file(sample_file, "")


def test_missing_input_file(tmp_path):
    with pytest.raises(FileNotFoundError):
        encrypt_file(tmp_path / "nope.txt", PASSWORD)
    with pytest.raises(FileNotFoundError):
        decrypt_file(tmp_path / "nope.txt.enc", PASSWORD)
