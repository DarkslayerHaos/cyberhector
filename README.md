## 🎯 Intended Use & Disclaimer

CyberHector is developed strictly as a **personal learning tool and educational proof-of-concept** for studying, implementing, and practicing modern hybrid post-quantum cryptography. 

- **Private & Educational Use Only:** This software is tailored for standalone, private, offline experimentation.
- **Not for Enterprise Deployment:** It is **not** intended, certified, or audited for commercial environments, production networks, corporate compliance environments, or general-purpose industrial data security.
- **As-Is Provision:** The source code is provided with zero corporate backing, maintenance guarantees, or formal cryptographic validation certifications.

---

> This repository contains the official production-grade C++ implementation of CyberHector, featuring an advanced Post-Quantum Hybrid Cryptographic design.

CyberHector is a local, high-security utility engineered to safeguard sensitive data against both classical threats and future quantum adversaries. It integrates state-of-the-art **Post-Quantum Cryptography (PQC)** for asymmetric key encapsulation with ultra-performant, chunk-streamed **Authenticated Encryption with Associated Data (AEAD)** for large file payloads. 

Designed for strict offline, single-user architectures with zero runtime network requirements.

---

## 🗝️ Asymmetric Post-Quantum Key Encapsulation (ML-KEM-768)

To achieve absolute mathematical immunity against Shor's algorithm and quantum-accelerated factorization attacks, CyberHector migrates all asymmetric routines to the **ML-KEM-768** primitive via OpenSSL 3.6+:

- **Lattice-Based Security:** Leverages the hardness of the *Module Learning with Errors (M-LWE)* mathematical problem over structured algebraic networks.
- **NIST Standard Compliance:** Implements the finalized Federal Information Processing Standard (FIPS 203) for key encapsulation mechanisms.
- **Cryptographic Key Wrap Flow:**
  - `cyberhector.exe` ingests a public PEM configuration to encapsulate an internal shared secret, producing an exactly **1,088-byte** key capsule (`KEM_CT`).
  - The shared secret is passed through an independent, custom **HKDF-BLAKE2b** primitive alongside a cryptographically secure 12-byte random salt to derive an isolated wrapping key.
  - The master session key is then encrypted via **XChaCha20-Poly1305** using the generated wrapping key and written to the flat structured `.ewk` artifact.
  - `cyberhector_keys.exe` loads the corresponding asymmetric PEM private key block, parses the capsule boundary from the `.ewk` payload via rigorous pointer slicing, decapsulates the shared secret natively via OpenSSL, re-derives the wrapping token, and exposes the decrypted session key back into disk space.

---

## 🔒 Symmetric Stream Encryption (XChaCha20-Poly1305)

File operations are designed to handle multi-gigabyte files (customizable) with minimal volatile memory consumption:

- **Chunked Data Streaming:** Files located within the target operational `Private Folder` directory are read sequentially in isolated **4 Megabyte (4,194,304 bytes)** block matrices.
- **Libsodium Secretstream API:** Uses `crypto_secretstream_xchacha20poly1305` to build sequential, non-replayable, state-dependent cipher streams. Each chunk is mathematically tied to its predecessor, entirely mitigating block deletion, chunk reordering, or packet injection attacks.
- **Extended Nonce Security:** The 192-bit nonce space of XChaCha20 eliminates any mathematical probability of nonce collision, making it fully safe to generate high-frequency randomized vectors under identical structural keys.

---

## 📁 File Processing & Anti-Forensic Deletion

- **Targeted Operations:** Ingests unencrypted file systems natively inside the predefined execution zone (`Private Folder`), outputting fully protected blobs wrapped with a `.cybr` file extension identifier.
- **Anti-Forensic Storage Purge:** When the recovery or decryption routine successfully finishes processing the directory, the `.ewk` file context goes through an automated security scrubbing mechanism:
  - **Memory Sanitization:** The 32-byte master session key array is instantly targeted in RAM via constant-time memory zeroing (`sodium_memzero`).
  - **Header Shredding:** The system accesses the physical `.ewk` disk address space, blocks standard OS caching mechanisms, securely overwrites the first 4KB blocks with randomized libsodium bytes to trurate the key structures, and then calls a native OS removal command. This fully defeats post-incident forensic disk extraction attempts or raw block scanning procedures (`Recuva`, data carving utilities, etc.).

---

## 📦 Dependencies & Implementation Pre-requisites

### 🔒 OpenSSL (v3.6.0 or Newer)
Leveraged exclusively for primitive post-quantum key management and mathematical operations:
- Native execution of **ML-KEM-768** (Module Lattice Key Encapsulation Mechanism) keypair initialization, encapsulation, and decapsulation routines.
- Standards-compliant cryptographic parsing of asymmetric private/public components represented through PEM blocks (`PEM_read_bio_PUBKEY` / `PEM_read_bio_PrivateKey`).

### 🧩 libsodium (Stable Release)
Acts as the engine for zero-trust symmetric tasks and system random layers:
- Sequential authenticated file data transformations via `crypto_secretstream_xchacha20poly1305`.
- Envelope layout payload wrapping using `crypto_aead_xchacha20poly1305_ietf`.
- Core cryptographic key generation and byte translation utilities (`sodium_base64_VARIANT_ORIGINAL`).
- Hardware-entropy random buffering via `randombytes_buf` and constant-time RAM cleansing (`sodium_memzero`).

---

## ⚠️ Critical Cryptographic Warning

Data protection inside this ecosystem relies **exclusively and uniquely** on the absolute validity of the asymmetric key infrastructure and the physical file persistence of the `.ewk` capsule. 

If the private key PEM container is lost or modified, or if the `.ewk` transport token gets corrupted before a successful run of `cyberhector_keys.exe`, your files are **permanently and mathematically lost**. This framework contains no administrative override mechanisms, no recovery fields, and no backdoor entry layers.
"""