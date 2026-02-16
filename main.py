from decrypt import decrypt
from encrypt import encrypt


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
