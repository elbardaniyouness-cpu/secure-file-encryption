import argparse
import getpass
import sys

from utils import EncryptionError, decrypt_file


def decrypt(file_path: str | None = None):
    if not file_path:
        file_path = input("Enter path to the encrypted file: ").strip()

    try:
        password = getpass.getpass("Enter password for decryption: ")
        output_file = decrypt_file(file_path, password)
    except (FileNotFoundError, ValueError, EncryptionError) as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        raise SystemExit(1) from exc

    print(f"[OK] File decrypted successfully: {output_file}")


def main():
    parser = argparse.ArgumentParser(description="Decrypt an AES-256 encrypted file.")
    parser.add_argument("file", nargs="?", help="Path to the encrypted file")
    args = parser.parse_args()
    decrypt(args.file)


if __name__ == "__main__":
    main()
