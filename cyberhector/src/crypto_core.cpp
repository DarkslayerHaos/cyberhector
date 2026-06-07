/**
 * @file crypto_core.cpp
 * @brief Core cryptographic functions using libsodium and OpenSSL 3.6 for ML-KEM-768.
 */

#include <sodium.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <vector>
#include <string>
#include <stdexcept>
#include <cstring>
#include "config.hpp"

/**
 * @namespace CryptoCore
 * @brief Internal cryptographic operations for key generation and wrapping.
 */
namespace CryptoCore
{
    /**
     * Manual HKDF implementation using BLAKE2b as the hash primitive.
     * Matches standard Extract-and-Expand design patterns.
     */
    void derive_hkdf_blake2b(unsigned char *okm, size_t okm_len,
                             const unsigned char *ikm, size_t ikm_len,
                             const unsigned char *salt, size_t salt_len,
                             const std::string &info)
    {
        unsigned char prk[64];

        // 1. HKDF-Extract: Keyed hash using the salt as the key over the IKM payload
        crypto_generichash_blake2b(prk, sizeof(prk), ikm, ikm_len, salt, salt_len);

        // 2. HKDF-Expand: Keyed hash using the generated PRK over info | counter
        crypto_generichash_blake2b_state state;
        crypto_generichash_blake2b_init(&state, prk, sizeof(prk), sizeof(prk));
        crypto_generichash_blake2b_update(&state, (const unsigned char *)info.c_str(), info.length());

        unsigned char counter = 0x01;
        crypto_generichash_blake2b_update(&state, &counter, 1);

        unsigned char full_output[64];
        crypto_generichash_blake2b_final(&state, full_output, sizeof(full_output));

        std::memcpy(okm, full_output, okm_len);

        sodium_memzero(prk, sizeof(prk));
        sodium_memzero(full_output, sizeof(full_output));
    }

    /**
     * Generates a 32-byte secure random symmetric key.
     */
    std::vector<unsigned char> generate_symkey()
    {
        std::vector<unsigned char> key(32);
        randombytes_buf(key.data(), 32);
        return key;
    }

    /**
     * Wraps the session key using ML-KEM-768 and XChaCha20-Poly1305.
     * Protocol Sync: MAGIC | VERSION | salt(12) | kem_ct(1088) | nonce(24) | ciphertext
     */
    std::string wrap_symkey(const std::vector<unsigned char> &symkey)
    {
        // 1. Load Recipient Public Key from PEM configuration string
        BIO *bio = BIO_new_mem_buf(Config::PUBLIC_KEY_PEM.data(), static_cast<int>(Config::PUBLIC_KEY_PEM.length()));
        if (!bio)
            throw std::runtime_error("Failed to allocate memory buffer for PEM context.");

        EVP_PKEY *pkey = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
        BIO_free(bio);

        if (!pkey)
            throw std::runtime_error("Failed to parse ML-KEM public key from PEM string config.");

        // 2. Setup KEM Context
        EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pkey, nullptr);
        if (!ctx || EVP_PKEY_encapsulate_init(ctx, nullptr) <= 0)
        {
            EVP_PKEY_free(pkey);
            if (ctx) EVP_PKEY_CTX_free(ctx);
            throw std::runtime_error("Failed to initialize OpenSSL KEM encapsulation context.");
        }

        // 3. Setup fixed buffer sizes for ML-KEM-768
        size_t secret_len = 32;
        size_t kem_ct_len = 1088; // Fixed capsule length for ML-KEM-768

        std::vector<unsigned char> shared_secret(secret_len);
        std::vector<unsigned char> kem_ciphertext(kem_ct_len);

        // 4. Perform Key Encapsulation (Generates Secret + Capsule Ciphertext)
        if (EVP_PKEY_encapsulate(ctx, kem_ciphertext.data(), &kem_ct_len, shared_secret.data(), &secret_len) <= 0)
        {
            EVP_PKEY_CTX_free(ctx);
            EVP_PKEY_free(pkey);
            throw std::runtime_error("ML-KEM-768 encapsulation execution failed.");
        }

        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);

        // 5. HKDF Key Derivation using BLAKE2b over generated shared secret context
        unsigned char salt[12];
        randombytes_buf(salt, 12);
        unsigned char wrapping_key[32];

        derive_hkdf_blake2b(wrapping_key, 32, shared_secret.data(), shared_secret.size(), salt, 12, Config::INFO);

        // 6. AEAD Protection layer (XChaCha20-Poly1305)
        unsigned char nonce[24];
        randombytes_buf(nonce, 24);

        // Authenticated Data structure: Apenas o cabeçalho base fixo (9 bytes)
        std::vector<unsigned char> corner_aad;
        corner_aad.insert(corner_aad.end(), Config::MAGIC.begin(), Config::MAGIC.end());
        corner_aad.push_back(Config::VERSION);

        // 7. Encrypt Symmetric Payload 
        std::vector<unsigned char> ct(symkey.size() + 16); // 16 bytes for Poly1305 MAC tag
        unsigned long long ct_len;
        if (crypto_aead_xchacha20poly1305_ietf_encrypt(ct.data(), &ct_len, symkey.data(), symkey.size(),
                                                       corner_aad.data(), corner_aad.size(), NULL, nonce, wrapping_key) != 0)
        {
            sodium_memzero(shared_secret.data(), shared_secret.size());
            sodium_memzero(wrapping_key, 32);
            throw std::runtime_error("Symmetric encryption over symmetric key material failed.");
        }

        // 8. Assemble structured flat artifact envelope layout sequence
        std::vector<unsigned char> pkg;
        pkg.insert(pkg.end(), corner_aad.begin(), corner_aad.end()); // MAGIC (8) + VERSION (1)
        pkg.insert(pkg.end(), salt, salt + 12);                      // SALT (12)
        pkg.insert(pkg.end(), kem_ciphertext.begin(), kem_ciphertext.end()); // KEM_CT (1088)
        pkg.insert(pkg.end(), nonce, nonce + 24);                    // NONCE (24)
        pkg.insert(pkg.end(), ct.begin(), ct.end());                 // CIPHERTEXT + TAG (48)

        // Memory cleanup
        sodium_memzero(shared_secret.data(), shared_secret.size());
        sodium_memzero(wrapping_key, 32);

        // 9. Process envelope serialization to Standard Base64 String format
        size_t b64_len = sodium_base64_encoded_len(pkg.size(), sodium_base64_VARIANT_ORIGINAL);
        std::vector<char> b64_out(b64_len);
        sodium_bin2base64(b64_out.data(), b64_out.size(), pkg.data(), pkg.size(), sodium_base64_VARIANT_ORIGINAL);

        return std::string(b64_out.data());
    }

    /**
     * Encrypts file data chunks using the internal symmetric key.
     */
    std::vector<unsigned char> encrypt_file_data(const std::vector<unsigned char> &symkey, const std::vector<unsigned char> &plain)
    {
        unsigned char nonce[24];
        randombytes_buf(nonce, 24);

        std::vector<unsigned char> aad;
        aad.insert(aad.end(), Config::MAGIC.begin(), Config::MAGIC.end());
        aad.push_back(Config::VERSION);

        std::vector<unsigned char> pkg = aad;
        pkg.insert(pkg.end(), nonce, nonce + 24);

        std::vector<unsigned char> ct(plain.size() + 16);
        unsigned long long ct_len;
        crypto_aead_xchacha20poly1305_ietf_encrypt(ct.data(), &ct_len, plain.data(), plain.size(),
                                                   aad.data(), aad.size(), NULL, nonce, symkey.data());

        pkg.insert(pkg.end(), ct.begin(), ct.end());
        return pkg;
    }

    /**
     * Decrypts file data chunks using the internal symmetric key.
     */
    std::vector<unsigned char> decrypt_file_data(const std::vector<unsigned char> &symkey, const std::vector<unsigned char> &pkg)
    {
        size_t header_len = Config::MAGIC.length() + 1;
        if (pkg.size() < (header_len + 24 + 16))
            throw std::runtime_error("Corrupted file package.");

        const unsigned char *nonce = pkg.data() + header_len;
        const unsigned char *ct = nonce + 24;
        size_t ct_len = pkg.size() - header_len - 24;

        std::vector<unsigned char> aad(pkg.begin(), pkg.begin() + header_len);
        std::vector<unsigned char> pt(ct_len - 16);
        unsigned long long pt_len;

        if (crypto_aead_xchacha20poly1305_ietf_decrypt(pt.data(), &pt_len, NULL, ct, ct_len,
                                                       aad.data(), aad.size(), nonce, symkey.data()) != 0)
        {
            throw std::runtime_error("File decryption failed: Auth error.");
        }

        return pt;
    }
}