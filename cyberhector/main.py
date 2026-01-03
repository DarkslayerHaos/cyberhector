from src.file_ops import encrypt_all_in_dir, decrypt_all_in_dir
from src.config import TARGET_DIR


def main():
    print("\n--- CyberHector File Encryption Utility ---")

    if not TARGET_DIR.exists() or not TARGET_DIR.is_dir():
        print("Target folder not found:", TARGET_DIR)
        return

    print(f"\n[1] Encrypt files in '{TARGET_DIR}' folder")
    print(f"[2] Decrypt files in '{TARGET_DIR}' folder")
    choice = input("Select an option: ").strip().lower()

    if choice == "1":
        try:
            encrypt_all_in_dir(TARGET_DIR)
        except Exception as e:
            print("Error during encryption:", type(e).__name__, e)
    elif choice == "2":
        try:
            decrypt_all_in_dir(TARGET_DIR)
        except Exception as e:
            print("Error during decryption:", type(e).__name__, e)
    else:
        print("Invalid option.")

if __name__ == "__main__":
    main()