/**
 * @file crypto_core.cpp
 * @brief Core cryptographic functions using libsodium and OpenSSL 3.6 for ML-KEM.
 */

#include <sodium.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/kdf.h>
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
     * HKDF key derivation using OpenSSL's native EVP_KDF interface with SHA-512.
     * Implements RFC 5869 Extract-and-Expand in a single call via the built-in provider.
     */
    void derive_hkdf(unsigned char *okm, size_t okm_len,
                     const unsigned char *ikm, size_t ikm_len,
                     const unsigned char *salt, size_t salt_len,
                     const std::string &info)
    {
        EVP_KDF *kdf = EVP_KDF_fetch(nullptr, "HKDF", nullptr);
        if (!kdf)
            throw std::runtime_error("Failed to fetch HKDF from OpenSSL provider.");

        EVP_KDF_CTX *kctx = EVP_KDF_CTX_new(kdf);
        EVP_KDF_free(kdf);
        if (!kctx)
            throw std::runtime_error("Failed to create HKDF context.");

        // Build parameter list: digest, key (IKM), salt, info, output length
        OSSL_PARAM params[] = {
            OSSL_PARAM_construct_utf8_string("digest", const_cast<char *>("SHA512"), 0),
            OSSL_PARAM_construct_octet_string("key", const_cast<unsigned char *>(ikm), ikm_len),
            OSSL_PARAM_construct_octet_string("salt", const_cast<unsigned char *>(salt), salt_len),
            OSSL_PARAM_construct_octet_string("info", const_cast<unsigned char *>(reinterpret_cast<const unsigned char *>(info.c_str())), info.length()),
            OSSL_PARAM_END};

        if (EVP_KDF_derive(kctx, okm, okm_len, params) <= 0)
        {
            EVP_KDF_CTX_free(kctx);
            throw std::runtime_error("HKDF derivation failed.");
        }

        EVP_KDF_CTX_free(kctx);
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
     * Wraps the session key using ML-KEM and XChaCha20-Poly1305.
     * Protocol Sync: MAGIC | VERSION | salt(12) | kem_ct | nonce(24) | ciphertext
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
            if (ctx)
                EVP_PKEY_CTX_free(ctx);
            throw std::runtime_error("Failed to initialize OpenSSL KEM encapsulation context.");
        }

        // 3. Setup fixed buffer sizes for ML-KEM
        size_t kem_ct_len = 0;
        size_t secret_len = 0;
        if (EVP_PKEY_encapsulate(ctx, nullptr, &kem_ct_len, nullptr, &secret_len) <= 0)
        {
            EVP_PKEY_CTX_free(ctx);
            EVP_PKEY_free(pkey);
            throw std::runtime_error("Failed to query KEM buffer sizes.");
        }

        std::vector<unsigned char> shared_secret(secret_len);
        std::vector<unsigned char> kem_ciphertext(kem_ct_len);

        // 4. Perform Key Encapsulation (Generates Secret + Capsule Ciphertext)
        if (EVP_PKEY_encapsulate(ctx, kem_ciphertext.data(), &kem_ct_len, shared_secret.data(), &secret_len) <= 0)
        {
            EVP_PKEY_CTX_free(ctx);
            EVP_PKEY_free(pkey);
            throw std::runtime_error("KEM encapsulation execution failed..");
        }

        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);

        // 5. HKDF-SHA256 key derivation over generated shared secret context
        unsigned char salt[12];
        randombytes_buf(salt, 12);
        unsigned char wrapping_key[32];

        derive_hkdf(wrapping_key, 32, shared_secret.data(), shared_secret.size(), salt, 12, Config::INFO);

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
        pkg.insert(pkg.end(), corner_aad.begin(), corner_aad.end());         // MAGIC (8) + VERSION (1)
        pkg.insert(pkg.end(), salt, salt + 12);                              // SALT (12)
        pkg.insert(pkg.end(), kem_ciphertext.begin(), kem_ciphertext.end()); // KEM_CT
        pkg.insert(pkg.end(), nonce, nonce + 24);                            // NONCE (24)
        pkg.insert(pkg.end(), ct.begin(), ct.end());                         // CIPHERTEXT + TAG (48)

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