#include <sodium.h>
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
        // BLAKE2b maximum output hash size is 64 bytes (crypto_generichash_BYTES_MAX)
        unsigned char prk[64];

        // 1. HKDF-Extract: Keyed hash using the salt as the key over the X25519 shared payload
        crypto_generichash_blake2b(prk, sizeof(prk), ikm, ikm_len, salt, salt_len);

        // 2. HKDF-Expand: Keyed hash using the generated PRK over info | counter
        crypto_generichash_blake2b_state state;
        crypto_generichash_blake2b_init(&state, prk, sizeof(prk), sizeof(prk));
        crypto_generichash_blake2b_update(&state, (const unsigned char *)info.c_str(), info.length());

        unsigned char counter = 0x01; // Standard iteration counter
        crypto_generichash_blake2b_update(&state, &counter, 1);

        unsigned char full_output[64];
        crypto_generichash_blake2b_final(&state, full_output, sizeof(full_output));

        // Copy required key size (32 bytes) to output wrapping key container
        std::memcpy(okm, full_output, okm_len);

        // Secure context zeroing
        sodium_memzero(prk, sizeof(prk));
        sodium_memzero(full_output, sizeof(full_output));
    }

    // Unwraps session key using private key bytes and BLAKE2b
    std::vector<unsigned char> decrypt_symkey_x25519(const std::string &b64_pkg, const unsigned char *priv_key)
    {
        std::vector<unsigned char> pkg(b64_pkg.length());
        size_t pkg_len;
        if (sodium_base642bin(pkg.data(), pkg.size(), b64_pkg.c_str(), b64_pkg.length(), NULL, &pkg_len, NULL, sodium_base64_VARIANT_ORIGINAL) != 0)
            throw std::runtime_error("Invalid Base64 capsule.");

        pkg.resize(pkg_len);
        size_t header_len = Config::MAGIC.length() + 1;
        const unsigned char *salt = pkg.data() + header_len;
        const unsigned char *eph_pub = salt + 12;
        const unsigned char *nonce = eph_pub + 32;
        const unsigned char *ct = nonce + 24;
        size_t ct_len = pkg_len - (header_len + 12 + 32 + 24);

        unsigned char shared[32];
        if (crypto_scalarmult(shared, priv_key, eph_pub) != 0)
            throw std::runtime_error("ECDH failed.");

        unsigned char wrapping_key[32];

        // --- SWITCHED FROM SHA512 TO BLAKE2b HERE ---
        derive_hkdf_blake2b(wrapping_key, 32, shared, 32, salt, 12, Config::INFO);

        std::vector<unsigned char> pt(ct_len - 16);
        unsigned long long pt_actual_len;
        if (crypto_aead_xchacha20poly1305_ietf_decrypt(pt.data(), &pt_actual_len, NULL, ct, ct_len, pkg.data(), header_len + 12 + 32, nonce, wrapping_key) != 0)
        {
            sodium_memzero(shared, 32);
            sodium_memzero(wrapping_key, sizeof(wrapping_key));
            throw std::runtime_error("Capsule integrity check failed.");
        }

        sodium_memzero(shared, 32);
        sodium_memzero(wrapping_key, sizeof(wrapping_key));
        return pt;
    }
}