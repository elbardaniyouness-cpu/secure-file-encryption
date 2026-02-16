from __future__ import annotations

from pathlib import Path
import os

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

SALT_SIZE = 16
IV_SIZE = 16
TAG_SIZE = 32
PBKDF2_ITERATIONS = 600_000


class EncryptionError(Exception):
    """Raised when encryption/decryption fails."""


def _derive_keys(password: str, salt: bytes) -> tuple[bytes, bytes]:
    if not password:
        raise ValueError("Password must not be empty.")

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=64,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    key_material = kdf.derive(password.encode("utf-8"))
    return key_material[:32], key_material[32:]


def _encrypted_output_path(file_path: Path) -> Path:
    return file_path.with_name(f"{file_path.name}.enc")


def _decrypted_output_path(file_path: Path) -> Path:
    if file_path.suffix == ".enc":
        return file_path.with_suffix(".dec")
    return file_path.with_name(f"{file_path.name}.dec")


def encrypt_file(file_path: str | Path, password: str) -> Path:
    input_path = Path(file_path)
    if not input_path.is_file():
        raise FileNotFoundError(f"Input file not found: {input_path}")

    plaintext = input_path.read_bytes()
    salt = os.urandom(SALT_SIZE)
    iv = os.urandom(IV_SIZE)
    enc_key, mac_key = _derive_keys(password, salt)

    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_plaintext = padder.update(plaintext) + padder.finalize()

    cipher = Cipher(algorithms.AES(enc_key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()

    # Authenticate metadata and ciphertext to detect tampering before decrypting.
    header = salt + iv
    hmac = HMAC(mac_key, hashes.SHA256())
    hmac.update(header + ciphertext)
    tag = hmac.finalize()

    output_path = _encrypted_output_path(input_path)
    output_path.write_bytes(header + tag + ciphertext)
    return output_path


def decrypt_file(file_path: str | Path, password: str) -> Path:
    input_path = Path(file_path)
    if not input_path.is_file():
        raise FileNotFoundError(f"Input file not found: {input_path}")

    file_data = input_path.read_bytes()
    min_size = SALT_SIZE + IV_SIZE + TAG_SIZE + 16
    if len(file_data) < min_size:
        raise EncryptionError("Encrypted file is too short or corrupted.")

    salt = file_data[:SALT_SIZE]
    iv = file_data[SALT_SIZE : SALT_SIZE + IV_SIZE]
    tag = file_data[SALT_SIZE + IV_SIZE : SALT_SIZE + IV_SIZE + TAG_SIZE]
    ciphertext = file_data[SALT_SIZE + IV_SIZE + TAG_SIZE :]
    enc_key, mac_key = _derive_keys(password, salt)

    hmac = HMAC(mac_key, hashes.SHA256())
    hmac.update(salt + iv + ciphertext)
    try:
        hmac.verify(tag)
    except InvalidSignature as exc:
        raise EncryptionError(
            "Integrity check failed (wrong password or modified file)."
        ) from exc

    cipher = Cipher(algorithms.AES(enc_key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    try:
        plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
    except ValueError as exc:
        raise EncryptionError(
            "Invalid padding; wrong password or corrupted data."
        ) from exc

    output_path = _decrypted_output_path(input_path)
    output_path.write_bytes(plaintext)
    return output_path
