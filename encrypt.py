import argparse
import getpass
import sys

from utils import EncryptionError, encrypt_file


def main():
    parser = argparse.ArgumentParser(description="Encrypt a file with AES-256.")
    parser.add_argument("file", help="Path to the file to encrypt")
    args = parser.parse_args()

    try:
        password = getpass.getpass("Enter password for encryption: ")
        output_file = encrypt_file(args.file, password)
    except (FileNotFoundError, ValueError, EncryptionError) as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        raise SystemExit(1) from exc

    print(f"[OK] File encrypted successfully: {output_file}")


if __name__ == "__main__":
    main()
