/**
 * @file crypto_core.cpp
 * @brief Core cryptographic functions using libsodium.
 */

#include <sodium.h>
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
     * Updated helper: HKDF-SHA512 (Extract and Expand).
     * Synchronized with Python's HKDF(algorithm=hashes.SHA512()).
     */
    void derive_hkdf_sha512(unsigned char *okm, size_t okm_len,
                            const unsigned char *ikm, size_t ikm_len,
                            const unsigned char *salt, size_t salt_len,
                            const std::string &info)
    {
        unsigned char prk[64]; // SHA512 output size is 64 bytes

        // 1. HKDF-Extract: HMAC-SHA512(salt, ikm)
        crypto_auth_hmacsha512_state state;
        crypto_auth_hmacsha512_init(&state, salt, salt_len);
        crypto_auth_hmacsha512_update(&state, ikm, ikm_len);
        crypto_auth_hmacsha512_final(&state, prk);

        // 2. HKDF-Expand: HMAC-SHA512(PRK, info | 0x01)
        // Since we only need 32 bytes (okm_len), we only perform one iteration.
        crypto_auth_hmacsha512_init(&state, prk, sizeof(prk));
        crypto_auth_hmacsha512_update(&state, (const unsigned char *)info.c_str(), info.length());

        unsigned char counter = 0x01; // RFC 5869 counter
        crypto_auth_hmacsha512_update(&state, &counter, 1);

        unsigned char full_output[64];
        crypto_auth_hmacsha512_final(&state, full_output);

        // Copy resulting key material to output buffer
        std::memcpy(okm, full_output, okm_len);

        // Cleanup
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
     * Wraps the session key using X25519 and XChaCha20-Poly1305.
     * Protocol Sync: MAGIC | VERSION | salt(12) | eph_pub(32) | nonce(24) | ciphertext
     */
    std::string wrap_symkey(const std::vector<unsigned char> &symkey)
    {
        // 1. Decode Master Public Key from Base64 string in config.hpp
        unsigned char raw_pub[32];
        size_t bin_len;
        if (sodium_base642bin(raw_pub, 32, Config::PUBLIC_KEY_B64.c_str(), Config::PUBLIC_KEY_B64.length(),
                              NULL, &bin_len, NULL, sodium_base64_VARIANT_ORIGINAL) != 0)
        {
            throw std::runtime_error("Invalid Base64 in PUBLIC_KEY_B64.");
        }

        // 2. Generate Ephemeral Keypair (Standard X25519)
        unsigned char eph_pub[32], eph_priv[32];
        if (crypto_box_keypair(eph_pub, eph_priv) != 0)
        {
            throw std::runtime_error("Failed to generate ephemeral keypair.");
        }

        // 3. ECDH Shared Secret (Static-Ephemeral)
        unsigned char shared[32];
        if (crypto_scalarmult(shared, eph_priv, raw_pub) != 0)
        {
            sodium_memzero(eph_priv, 32);
            throw std::runtime_error("ECDH failed: Invalid public key.");
        }

        // 4. HKDF Key Derivation
        unsigned char salt[12];
        randombytes_buf(salt, 12);
        unsigned char wrapping_key[32];
        derive_hkdf_sha512(wrapping_key, 32, shared, 32, salt, 12, Config::INFO);

        // 5. AEAD Encryption Setup
        unsigned char nonce[24];
        randombytes_buf(nonce, 24);

        // AAD MUST match Python: MAGIC + VERSION + SALT + EPH_PUB
        std::vector<unsigned char> aad;
        aad.insert(aad.end(), Config::MAGIC.begin(), Config::MAGIC.end());
        aad.push_back(Config::VERSION);
        aad.insert(aad.end(), salt, salt + 12);
        aad.insert(aad.end(), eph_pub, eph_pub + 32);

        // 6. Encrypt Session Key
        std::vector<unsigned char> ct(symkey.size() + 16); // 16 bytes for Poly1305 MAC
        unsigned long long ct_len;
        if (crypto_aead_xchacha20poly1305_ietf_encrypt(ct.data(), &ct_len, symkey.data(), symkey.size(),
                                                       aad.data(), aad.size(), NULL, nonce, wrapping_key) != 0)
        {
            throw std::runtime_error("AEAD encryption failed.");
        }

        // 7. Assemble binary package for Base64 encoding
        // Structure: [AAD (Magic+Ver+Salt+EphPub)] + [Nonce] + [Ciphertext]
        std::vector<unsigned char> pkg = aad;
        pkg.insert(pkg.end(), nonce, nonce + 24);
        pkg.insert(pkg.end(), ct.begin(), ct.end());

        // Cleanup sensitive data
        sodium_memzero(eph_priv, 32);
        sodium_memzero(shared, 32);
        sodium_memzero(wrapping_key, 32);

        // 8. Return as Base64 string for .ewk file
        size_t b64_len = sodium_base64_encoded_len(pkg.size(), sodium_base64_VARIANT_ORIGINAL);
        std::vector<char> b64_out(b64_len);
        sodium_bin2base64(b64_out.data(), b64_out.size(), pkg.data(), pkg.size(), sodium_base64_VARIANT_ORIGINAL);

        return std::string(b64_out.data());
    }

    /**
     * Encrypts file data using the session key.
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
     * Decrypts file data using the session key.
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