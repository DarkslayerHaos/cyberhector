# CyberHector

CyberHector is a local C++ proof of concept for hybrid post-quantum file encryption. It is inspired by the file-locking workflow used by ransomware, but built for personal, legitimate, offline use: encrypting your own files with your own keys, under your own control.

It is not production or enterprise software, and it has not been independently audited or formally certified.

## How it works

CyberHector splits key management and file processing into two separate binaries:

- **`cyberhector.exe`** — encrypts and decrypts the files themselves.
- **`cyberhector_keys.exe`** — generates the ML-KEM keypair and unwraps the session key before decryption.

This separation means the private key never has to sit next to the files it protects. The public key is embedded in `cyberhector.exe` at build time; the private key stays wherever you choose to keep it, ideally offline.

### Encryption flow

1. `cyberhector.exe` generates a random 32-byte session key.
2. The session key is wrapped: encapsulated via ML-KEM-1024 against the embedded public key, then sealed with HKDF-derived XChaCha20-Poly1305. The result is written as a Base64 capsule to an `.ewk` file.
3. Every eligible file inside `Private Folder` (recursively) is streamed through libsodium's `crypto_secretstream_xchacha20poly1305` in 4 MB chunks and written out with a `.cybr` extension.
4. The original file's first 2 MB are overwritten with random bytes before deletion (see "Secure deletion" below).
5. The session key is wiped from memory with `sodium_memzero` once encryption finishes.

### Decryption flow

1. `cyberhector_keys.exe` uses the private key (PEM, optionally password-protected) to decapsulate the `.ewk` capsule and recover the session key.
2. `cyberhector.exe` reads the recovered key, streams through every `.cybr` file in `Private Folder`, verifies the stream's authentication tag and the embedded header/version, and restores the original file.
3. The `.ewk` file is shredded after a successful recovery.

## Cryptography

- **Key encapsulation:** ML-KEM-1024, via OpenSSL 3.6+'s native `EVP_PKEY` KEM interface.
- **Key derivation:** HKDF-SHA512 (RFC 5869), via OpenSSL's `EVP_KDF`, with a random 12-byte salt per wrap.
- **Key protection:** XChaCha20-Poly1305 (AEAD), sealing the session key with the HKDF-derived wrapping key. Authenticated data includes a fixed `MAGIC | VERSION` header.
- **File encryption:** libsodium's `crypto_secretstream_xchacha20poly1305`, streamed in 4 MB chunks with proper final-chunk tagging.
- **Random generation:** libsodium's `randombytes_buf` for keys, salts, and nonces.
- **Key handling:** `sodium_memzero` clears the session key and intermediate secrets after use in the normal (non-error) path.

## File workflow

| Item | Default |
|---|---|
| Target directory | `Private Folder` (recursive) |
| Encrypted file extension | `.cybr` |
| Key capsule file | `00000000.ewk` |
| Max file size | 20 GB |
| Chunk size | 4 MB |

Files are matched by the configured constants in `src/config.hpp`— changing the target directory, extension, or key filename only requires editing that file.

### Secure deletion

After a file is encrypted, `secure_shred_head` overwrites the first 2 MB of the original (or the whole file, if smaller) with cryptographically random bytes before removing it. This is a best-effort step, not a guarantee: whether the underlying bytes are actually unrecoverable depends on the filesystem, the storage device (SSDs with wear leveling in particular), and OS-level caching. The same caveat applies to `.ewk` shredding after decryption.

## Requirements

- **OpenSSL 3.6 or newer** — required for ML-KEM support and PEM key handling.
- **libsodium** — authenticated streaming encryption, secure randomness, and memory-clearing utilities.
- **C++20 compiler** — developed and tested with `g++` via MSYS2 (MinGW `ucrt64`).

## Building

Both binaries are built with their respective `Makefile`:

```sh
make
```

Build flags enable `-O3`, stack protection (`-fstack-protector-strong`), and a statically linked, stripped executable with no external DLL dependencies. Some flags (`-fvisibility=hidden`, `-fomit-frame-pointer`) raise the baseline effort needed to read a disassembly, but they are not a substitute for the cryptography — the actual security of the files comes from ML-KEM and XChaCha20-Poly1305, not from how hard the binary is to read.

## Important warnings

- **Back up your private key.** If it's lost, or if the `.ewk` capsule is damaged before decryption, encrypted files are unrecoverable. There is no backdoor and no recovery path by design.
- **Test the full round trip on nonessential files first.** Encrypt, then decrypt, before trusting this with anything you care about.
- **This is a learning project.** It has not been reviewed by a third party and should not be treated as hardened against a determined, well-resourced attacker. It is built for personal, offline use against your own files.

CyberHector is provided as-is, without guarantees of maintenance, security, or fitness for any particular purpose.
