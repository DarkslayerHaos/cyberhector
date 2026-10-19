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
     * Decrypts a Base64-encoded package using a KEM PEM private key file.
     * KEM ciphertext and shared secret sizes are queried dynamically from OpenSSL,
     * so only the PEM key and config.hpp need to change when switching KEM algorithms.
     */
    std::vector<unsigned char> decrypt_symkey_ml_kem(const std::string &b64_pkg, const std::string &pem_priv_key)
    {
        // 1. Convert Base64 payload wrapper container back into binary data stream
        std::vector<unsigned char> pkg(b64_pkg.length());
        size_t pkg_len;
        if (sodium_base642bin(pkg.data(), pkg.size(), b64_pkg.c_str(), b64_pkg.length(), NULL, &pkg_len, NULL, sodium_base64_VARIANT_ORIGINAL) != 0)
            throw std::runtime_error("Invalid Base64 capsule.");

        pkg.resize(pkg_len);

        // 2. Load Private Key early so we can query KEM sizes before slicing the package
        BIO *bio = BIO_new_mem_buf(pem_priv_key.data(), static_cast<int>(pem_priv_key.length()));
        if (!bio)
            throw std::runtime_error("Failed to allocate memory buffer for private PEM context.");

        // Allocate a secure local buffer for the passphrase
        char password_buf[256];
        std::memset(password_buf, 0, sizeof(password_buf));

        // EVP_read_pw_string hides typed input; prompts only if the PEM is encrypted
        if (EVP_read_pw_string(password_buf, sizeof(password_buf), "[>] Enter PEM password: ", 0) != 0)
        {
            BIO_free(bio);
            throw std::runtime_error("Failed to read password or operation canceled.");
        }

        // Pass the manually collected password to the OpenSSL PEM reader
        EVP_PKEY *pkey = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, password_buf);

        // Securely erase the passphrase from memory immediately after use
        sodium_memzero(password_buf, sizeof(password_buf));
        BIO_free(bio);

        if (!pkey)
        {
            // Log that the key parsing failed, which typically indicates an incorrect password
            std::fprintf(stderr, "Error: Failed to parse KEM private key. Incorrect password or corrupted key structure.\n");
            throw std::runtime_error("Failed to parse KEM private key from PEM representation.");
        }

        // 3. Setup OpenSSL Context for Decapsulation
        EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pkey, nullptr);
        if (!ctx || EVP_PKEY_decapsulate_init(ctx, nullptr) <= 0)
        {
            EVP_PKEY_free(pkey);
            if (ctx)
                EVP_PKEY_CTX_free(ctx);
            throw std::runtime_error("Failed to initialize OpenSSL KEM decapsulation context.");
        }

        // 4. Query KEM sizes dynamically from the loaded key.
        //    EVP_PKEY_get_size returns the KEM ciphertext length for KEM keys.
        //    shared_len is always 32 bytes for all ML-KEM variants per NIST spec.
        size_t kem_ct_len = static_cast<size_t>(EVP_PKEY_get_size(pkey));
        size_t shared_len = 32;

        // 5. Strict protocol layout verification using the queried sizes
        size_t header_len = Config::MAGIC.length() + 1; // MAGIC (8) + VERSION (1)

        if (pkg_len < (header_len + 12 + kem_ct_len + 24 + 16))
            throw std::runtime_error("Corrupted key capsule structural payload footprint.");

        // 6. Exact Pointer Math Offset Slicing
        const unsigned char *salt = pkg.data() + header_len;
        const unsigned char *kem_ct = salt + 12;
        const unsigned char *nonce = kem_ct + kem_ct_len;
        const unsigned char *ct = nonce + 24;
        size_t aead_ct_len = pkg_len - (header_len + 12 + kem_ct_len + 24);

        // 7. Decapsulate internal payload safely using OpenSSL Primitive Engine
        std::vector<unsigned char> shared(shared_len);
        if (EVP_PKEY_decapsulate(ctx, shared.data(), &shared_len, kem_ct, kem_ct_len) <= 0)
        {
            EVP_PKEY_CTX_free(ctx);
            EVP_PKEY_free(pkey);
            throw std::runtime_error("KEM decapsulation failed.");
        }

        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);

        // 8. Re-derive wrapping key material using OpenSSL native HKDF-SHA256
        unsigned char wrapping_key[32];
        derive_hkdf(wrapping_key, 32, shared.data(), shared.size(), salt, 12, Config::INFO);

        // 9. Isolate AAD footprint to match signature verification validation scopes
        std::vector<unsigned char> corner_aad(pkg.begin(), pkg.begin() + header_len);

        // 10. Execute authenticated symmetric data decryption mapping
        std::vector<unsigned char> pt(aead_ct_len - 16);
        unsigned long long pt_actual_len;

        if (crypto_aead_xchacha20poly1305_ietf_decrypt(pt.data(), &pt_actual_len, NULL, ct, aead_ct_len,
                                                       corner_aad.data(), corner_aad.size(), nonce, wrapping_key) != 0)
        {
            sodium_memzero(shared.data(), shared.size());
            sodium_memzero(wrapping_key, 32);
            throw std::runtime_error("Session key decryption failed: Authenticated tag mismatch.");
        }

        // Cleanup tracking states
        sodium_memzero(shared.data(), shared.size());
        sodium_memzero(wrapping_key, 32);

        return pt;
    }
}