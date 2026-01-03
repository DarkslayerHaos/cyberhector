# CyberHector – Personal Hybrid Encryption System

> This repository contains **two official implementations** of CyberHector:
> 
> - 🔸 **C++ version** — [`main`](https://github.com/DarkslayerHaos/cyberhector/tree/main)
> - 🔹 **Python version** — [`python`](https://github.com/DarkslayerHaos/cyberhector/tree/python)
> 
> See each branch’s README for build and usage details.

This project implements a modern hybrid encryption system written in Python. It combines **X25519** for secure session-key encapsulation and **XChaCha20-Poly1305** for authenticated encryption of file contents.  
Designed for offline, single-user usage with strong cryptographic guarantees.

---

## 🔐 Hybrid Encryption Model
- A random **32-byte symmetric key** is generated locally.
- This key is **wrapped (encapsulated)** using X25519 Diffie–Hellman with the recipient’s public key.
- The wrapped key is stored in a **`.ewk` capsule file**.

---

## 🗝️ Asymmetric Key Encapsulation (X25519)
- Curve25519 ECDH is used to derive a shared secret between:
  - a locally generated **ephemeral keypair**, and  
  - the **user-embedded public key**.
- Provides strong forward secrecy and resistance to classical RSA-style factorization attacks.

---

## 🔒 Symmetric Encryption (XChaCha20-Poly1305)
- Ensures **confidentiality and integrity** of encrypted files.
- Uses a **24-byte nonce**, drastically expanding nonce space and reducing collision risks.
- Ideal for offline systems without persistent nonce tracking.

---

## 🔧 HKDF-SHA512 Key Derivation
Derives the wrapping key from the ECDH shared secret using:

- **HKDF (Extract + Expand)**  
- **SHA512 HMAC**

Provides strong diffusion, collision resistance, and resilience against length-extension issues.

---

## 📦 Encapsulation Package Format
The wrapped key stored in the `.ewk` capsule contains:

```
MAGIC | VERSION | salt(12) | eph_pub(32) | nonce(24) | ciphertext
```

This structure enables deterministic unwrapping and integrity validation.

---

## 📁 File Processing Behavior
- Encrypts all files inside the **“Private Folder”** directory.
- Produces encrypted files with a **`.cybr`** extension.
- Optionally removes original plaintext files.
- Decrypts `.cybr` files back to their original form.
- Removes `.ewk` after successful decryption to prevent reuse.

Fully offline, no network communication, no remote key exchange.

---

## ⚠️ Important
File recovery depends **exclusively** on the symmetric key contained in `00000000.ewk`.  
If this capsule is lost or corrupted, **recovery is impossible**.  
There are no backdoors, override keys, or emergency recovery features.

---

## 🎯 Intended Use
A personal learning tool for studying and practicing modern hybrid encryption.  
Designed strictly for **private, offline** usage.  
Not intended as a general-purpose or commercial encryption product.

---

## 📦 Dependencies

### 🧩 cryptography
Used for:
- X25519 (Curve25519) ECDH
- HKDF with SHA512
- Key serialization

### 🧩 PyNaCl
Used for:
- XChaCha20-Poly1305 AEAD

### 🧩 Python 3.10+
Required to run the CLI tool.