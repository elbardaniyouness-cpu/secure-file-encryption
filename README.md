# Secure File Encryption Tool

This project is a Python AES-256 file encryption and decryption tool. It lets you encrypt any file with a password and decrypt it later.

## Features
- AES-256-CBC encryption
- PBKDF2 key derivation (SHA-256)
- Separate encryption and authentication keys
- HMAC-SHA256 integrity verification for metadata + ciphertext
- Simple CLI for encryption and decryption

## Technologies
- Python 3
- `cryptography` library

## How it works
1. The user provides a file path and password.
2. The tool generates a random salt and IV.
3. PBKDF2 derives two keys from the password and salt.
4. The file is encrypted with AES-256-CBC.
5. HMAC authenticates `salt || iv || ciphertext`.
6. The file can be decrypted only with the correct password.

## Quick start (Windows / PowerShell)
1. Activate venv:
   - `\.venv\Scripts\Activate.ps1`
2. Install dependencies:
   - `pip install -r requirements.txt`
3. Encrypt a file:
   - `python encrypt.py path\to\file.txt` -> creates `file.txt.enc`
4. Decrypt a file:
   - `python decrypt.py path\to\file.txt.enc` -> creates `file.txt.dec`

## File format
- `salt(16) || iv(16) || hmac-tag(32) || ciphertext`

## Notes
- This is a learning project. For production use, consider AEAD modes like AES-GCM and streaming for very large files.
