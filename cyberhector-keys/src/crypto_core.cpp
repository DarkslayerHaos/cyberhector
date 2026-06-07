#include <sodium.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <vector>
#include <string>
#include <stdexcept>
#include <cstring>
#include "config.hpp"

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

        // 1. HKDF-Extract: Keyed hash using the salt as the key over the KEM shared secret
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
     * Decrypts a Base64-encoded package using a ML-KEM PEM private key file.
     */
    std::vector<unsigned char> decrypt_symkey_ml_kem(const std::string &b64_pkg, const std::string &pem_priv_key)
    {
        // 1. Convert Base64 payload wrapper container back into binary data stream
        std::vector<unsigned char> pkg(b64_pkg.length());
        size_t pkg_len;
        if (sodium_base642bin(pkg.data(), pkg.size(), b64_pkg.c_str(), b64_pkg.length(), NULL, &pkg_len, NULL, sodium_base64_VARIANT_ORIGINAL) != 0)
            throw std::runtime_error("Invalid Base64 capsule.");

        pkg.resize(pkg_len);

        // 2. Strict Protocol limits verification
        size_t header_len = Config::MAGIC.length() + 1; // MAGIC (8) + VERSION (1)
        const size_t ml_kem_ct_len = 1088;              // ML-KEM-768 ciphertext length

        // Minimum package requirement layout check
        if (pkg_len < (header_len + 12 + ml_kem_ct_len + 24 + 16))
            throw std::runtime_error("Corrupted key capsule structural payload footprint.");

        // 3. Exact Pointer Math Offset Slicing
        const unsigned char *salt = pkg.data() + header_len;
        const unsigned char *kem_ct = salt + 12;
        const unsigned char *nonce = kem_ct + ml_kem_ct_len;
        const unsigned char *ct = nonce + 24;
        size_t aead_ct_len = pkg_len - (header_len + 12 + ml_kem_ct_len + 24);

        // 4. Load Private Key from operational PEM block representation
        BIO *bio = BIO_new_mem_buf(pem_priv_key.data(), static_cast<int>(pem_priv_key.length()));
        if (!bio)
            throw std::runtime_error("Failed to allocate memory buffer for private PEM context.");

        // Allocate a secure local buffer for the passphrase
        char password_buf[256];
        std::memset(password_buf, 0, sizeof(password_buf));

        // Substitui o printf/fgets por uma função segura do OpenSSL que oculta o texto
        // Parâmetros: buffer, tamanho máximo, prompt na tela, modo de verificação (0 = não pede para confirmar)
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
            std::fprintf(stderr, "Error: Failed to parse ML-KEM private key. Incorrect password or corrupted key structure.\n");
            throw std::runtime_error("Failed to parse ML-KEM private key from PEM representation.");
        }

        // 5. Setup OpenSSL Context for Decapsulation
        EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pkey, nullptr);
        if (!ctx || EVP_PKEY_decapsulate_init(ctx, nullptr) <= 0)
        {
            EVP_PKEY_free(pkey);
            if (ctx)
                EVP_PKEY_CTX_free(ctx);
            throw std::runtime_error("Failed to initialize OpenSSL KEM decapsulation context.");
        }

        size_t shared_len = 32; // ML-KEM-768 shared secret outputs exactly 32 bytes
        std::vector<unsigned char> shared(shared_len);

        // 6. Decapsulate internal payload safely using OpenSSL 3.6 Primitive Engine
        if (EVP_PKEY_decapsulate(ctx, shared.data(), &shared_len, kem_ct, ml_kem_ct_len) <= 0)
        {
            EVP_PKEY_CTX_free(ctx);
            EVP_PKEY_free(pkey);
            throw std::runtime_error("KEM decapsulation failed.");
        }

        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);

        // 7. Re-derive wrapping key material using internal BLAKE2b HKDF mechanism
        unsigned char wrapping_key[32];
        derive_hkdf_blake2b(wrapping_key, 32, shared.data(), shared.size(), salt, 12, Config::INFO);

        // 8. Isolate AAD footprint to match signature verification validation scopes
        std::vector<unsigned char> corner_aad(pkg.begin(), pkg.begin() + header_len);

        // 9. Execute authenticated symmetric data decryption mapping
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