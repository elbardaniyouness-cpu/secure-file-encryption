# Secure File Encryption

[![CI](https://github.com/elbardaniyouness-cpu/secure-file-encryption/actions/workflows/ci.yml/badge.svg)](https://github.com/elbardaniyouness-cpu/secure-file-encryption/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/python-3.10%2B-3776AB?logo=python&logoColor=white)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

A command-line tool that encrypts and decrypts any file with a password, using **AES-256-CBC**, **PBKDF2-HMAC-SHA256** key derivation and **HMAC-SHA256** integrity checks (encrypt-then-MAC). A wrong password or a single modified byte is detected before anything is decrypted.

## Features

- AES-256-CBC encryption with a fresh random salt and IV for every file
- PBKDF2-HMAC-SHA256 key derivation with 600,000 iterations (the current OWASP recommendation)
- Separate keys for encryption and authentication, both derived from the password
- HMAC-SHA256 over the salt, IV and ciphertext, so tampering with any part of the file is caught
- Constant-time tag verification (via the `cryptography` library) before decryption starts
- Hidden password input, clear error messages, and no output file written when decryption fails
- 25 automated tests run on every push with GitHub Actions

## Demo

```text
$ python main.py
Welcome to the Secure File Encryption Tool!
Please choose an option:
1. Encrypt a file
2. Decrypt a file
Enter your choice (1 or 2): 1
Enter path to the file to encrypt: report.pdf
Password input is hidden. Type your password and press Enter.
Enter password for encryption:
[OK] File encrypted successfully: report.pdf.enc

$ python decrypt.py report.pdf.enc
Enter password for decryption:
[ERROR] Integrity check failed (wrong password or modified file).
```

## How it works

```text
password ──► PBKDF2-HMAC-SHA256 (random 16-byte salt, 600k iterations) ──► 64 bytes
                                                                            ├─ 32 bytes: AES-256 key
                                                                            └─ 32 bytes: HMAC key

plaintext ──► PKCS7 padding ──► AES-256-CBC (random 16-byte IV) ──► ciphertext
salt ‖ IV ‖ ciphertext ──► HMAC-SHA256 ──► 32-byte tag
```

**Encrypted file layout**

| Bytes | Field | Purpose |
|------:|-------|---------|
| 16 | Salt | Makes each derived key unique, even for the same password |
| 16 | IV | Randomises the first AES block |
| 32 | HMAC tag | Authenticates salt, IV and ciphertext |
| n × 16 | Ciphertext | AES-256-CBC output (PKCS7 padded) |

To decrypt, the tool re-derives both keys from the password and stored salt, verifies the HMAC tag, and only then decrypts and removes the padding. Checking the tag first (encrypt-then-MAC) protects against padding-oracle and tampering attacks.

## Getting started

Requires Python 3.10 or newer.

```bash
git clone https://github.com/elbardaniyouness-cpu/secure-file-encryption.git
cd secure-file-encryption
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

## Usage

Interactive menu:

```bash
python main.py
```

Or call the scripts directly:

```bash
python encrypt.py path/to/file.txt        # creates path/to/file.txt.enc
python decrypt.py path/to/file.txt.enc    # creates path/to/file.txt.dec
```

## Running the tests

```bash
pip install -r requirements-dev.txt
pytest -v          # 25 tests
ruff check .       # linting
```

The suite covers round trips for empty, small, block-aligned and large files, unique salts per encryption, wrong passwords, tampering with each part of the file (salt, IV, tag, ciphertext), truncated files, empty passwords, missing files, and the CLI entry points.

## Project structure

```text
secure-file-encryption/
├── utils.py              # Key derivation, encryption, decryption, file format
├── encrypt.py            # CLI: encrypt a file
├── decrypt.py            # CLI: decrypt a file
├── main.py               # Interactive menu (retries on wrong password)
├── tests/
│   ├── test_utils.py     # Crypto and file-format tests
│   └── test_cli.py       # Command-line tests
├── .github/workflows/
│   └── ci.yml            # Lint + tests on Python 3.10, 3.12, 3.13
├── requirements.txt
└── requirements-dev.txt
```

## Limitations and next steps

This is a learning project and has not been independently audited. Known trade-offs:

- **Whole file in memory.** Files are read and encrypted in one go; very large files would need streaming encryption.
- **CBC + HMAC instead of AEAD.** The design is sound, but an AEAD mode such as AES-GCM or ChaCha20-Poly1305 would do encryption and authentication in one step.
- **PBKDF2.** A memory-hard KDF such as Argon2id would resist GPU password cracking better.
- **No format version byte.** Adding one would allow the format to evolve without breaking old files.

## Author

**Youness El Bardani** · [LinkedIn](https://www.linkedin.com/in/youness-el-bardani) · [GitHub](https://github.com/elbardaniyouness-cpu)

## License

[MIT](LICENSE)
