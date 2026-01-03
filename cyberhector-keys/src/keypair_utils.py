import base64
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519
from .crypto_core import _zeroize_bytes, decrypt_symkey_x25519
from .config import EWK_PATH, PRIVATE_KEY_B64

def _generate_x25519_keys_core():
    """
    Utility to generate a new keypair if needed.
    Returns keys as Base64 strings for manual copy-paste into config files.
    """
    priv = x25519.X25519PrivateKey.generate()
    pub = priv.public_key()

    priv_bytes = priv.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption()
    )
    pub_bytes = pub.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )

    return base64.b64encode(priv_bytes).decode(), base64.b64encode(pub_bytes).decode()

def generate_keys_action():
    """
    Prints new keys to the console so the user can update config.py/config.hpp.
    """
    priv_b64, pub_b64 = _generate_x25519_keys_core()
    print("\n--- NEW KEYPAIR GENERATED ---")
    print(f"PUBLIC KEY (Base64):  {pub_b64}")
    print(f"PRIVATE KEY (Base64): {priv_b64}")
    print("-----------------------------\n")
    print("Copy these strings to your config.py and config.hpp files.")

def load_private_key():
    """
    Loads the X25519 private key directly from the Base64 string in config.py.
    """
    raw_bytes = base64.b64decode(PRIVATE_KEY_B64)
    return x25519.X25519PrivateKey.from_private_bytes(raw_bytes)

def decrypt_wrapped_key():
    """
    Unwraps the .ewk capsule and overwrites it with the raw session key.
    """
    if not EWK_PATH.exists():
        print(f"[-] Error: {EWK_PATH} not found.")
        return

    symkey = None
    try:
        # 1. Load the master private key from config string
        priv = load_private_key()
        
        # 2. Read the Base64 capsule (.ewk)
        wrapped_b64 = EWK_PATH.read_bytes().strip()

        # 3. Decrypt/Unwrap the session key
        print("[>] Unwrapping session key...")
        symkey = decrypt_symkey_x25519(priv, wrapped_b64)
        
        # 4. Save the raw session key back as Base64 (for the main decryptor)
        EWK_PATH.write_bytes(base64.b64encode(symkey))
        print("[+] Success: Session key unwrapped and saved to disk.")

    except Exception as e:
        print(f"[-] Unwrap failed: {e}")
    finally:
        if symkey:
            _zeroize_bytes(symkey)