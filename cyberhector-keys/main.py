from src.keypair_utils import generate_keys_action, decrypt_wrapped_key

def main():
    print("\n--- CyberHector Key Utility (Python) ---")
    print("[1] Unwrap Key Capsule (Decrypts .ewk)")
    print("[2] Generate New X25519 Key Pair (Console Output)")
    
    choice = input("Select an option: ").strip().lower()

    if choice == "1":
        decrypt_wrapped_key()
    elif choice == "2":
        generate_keys_action()
    else:
        print("Invalid option.")

if __name__ == "__main__":
    main()