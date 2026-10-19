# CyberHector

CyberHector is a local C++ proof of concept for learning about hybrid post-quantum cryptography and file encryption. It is intended for personal, offline experimentation—not production or enterprise use. It has not been presented here as independently audited or formally certified.

## Cryptography

- **Key encapsulation:** ML-KEM-1024, provided by OpenSSL 3.6 or newer.
- **Key derivation:** HKDF-SHA512 with a random salt, as implemented by the project.
- **Key protection:** XChaCha20-Poly1305.
- **File encryption:** libsodium's `crypto_secretstream_xchacha20poly1305`, processing files in chunks.
- **Key handling:** The project uses `sodium_memzero` to clear the session-key buffer from memory.

## File workflow

The application processes files in the `Private Folder` directory and writes encrypted files with the `.cybr` extension. Key material is stored in an `.ewk` file and is handled by `cyberhector.exe` and `cyberhector_keys.exe` as part of the encryption and recovery workflow.

The project also attempts to remove `.ewk` key material after successful recovery. This should not be treated as a guarantee of secure deletion: actual recovery may depend on the filesystem, storage device, and operating system.

## Requirements

- **OpenSSL 3.6 or newer** — ML-KEM and PEM key handling.
- **libsodium** — authenticated streaming encryption, random number generation, and memory-clearing utilities.

## Important warning

Keep secure backups of the private key and any required `.ewk` files. If the private key is lost or the key material is damaged, encrypted files may be unrecoverable. Test the complete recovery process with nonessential files before relying on the software.

CyberHector is provided as-is, without guarantees of maintenance, security, or suitability for any particular purpose.