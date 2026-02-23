import getpass
import sys

from utils import EncryptionError, decrypt_file, encrypt_file


def encrypt(file_path: str | None = None):
    if not file_path:
        file_path = input("Enter path to the file to encrypt: ").strip()

    try:
        print("Password input is hidden. Type your password and press Enter.")
        password = getpass.getpass("Enter password for encryption: ")
        output_file = encrypt_file(file_path, password)
    except (FileNotFoundError, ValueError, EncryptionError) as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        raise SystemExit(1) from exc

    print(f"[OK] File encrypted successfully: {output_file}")


def decrypt(file_path: str | None = None):
    if not file_path:
        file_path = input("Enter path to the encrypted file: ").strip()

    while True:
        try:
            print("Password input is hidden. Type your password and press Enter.")
            password = getpass.getpass("Enter password for decryption: ")
            output_file = decrypt_file(file_path, password)
            print(f"[OK] File decrypted successfully: {output_file}")
            return
        except (FileNotFoundError, ValueError) as exc:
            print(f"[ERROR] {exc}", file=sys.stderr)
            raise SystemExit(1) from exc
        except KeyboardInterrupt:
            print("\n[INFO] Decryption cancelled.")
            raise SystemExit(1)
        except EncryptionError:
            print("[ERROR] Wrong password. Please try again.", file=sys.stderr)


def main():
    print("Welcome to the Secure File Encryption Tool!")
    print("Please choose an option:")
    print("1. Encrypt a file")
    print("2. Decrypt a file")
    choice = input("Enter your choice (1 or 2): ").strip()

    if choice == "1":
        encrypt()
    elif choice == "2":
        decrypt()
    else:
        print("[ERROR] Invalid choice. Please enter 1 or 2.")
        raise SystemExit(1)


if __name__ == "__main__":
    main()
