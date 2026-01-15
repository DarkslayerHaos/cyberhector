/**
 * @file keypair_utils.cpp
 * @brief Utilities for managing X25519 keypairs and session key unwrapping.
 */

#include <iostream>
#include <fstream>
#include <vector>
#include <sodium.h>
#include "config.hpp"

/**
 * @namespace CryptoCore
 * @brief Internal cryptographic operations for key generation and wrapping.
 */
namespace CryptoCore
{
    /** @brief Decrypts a Base64-encoded package using an X25519 private key.*/
    std::vector<unsigned char> decrypt_symkey_x25519(const std::string &b64_pkg, const unsigned char *priv_key);
}

/**
 * @namespace KeyPairUtils
 * @brief Logic for generating X25519 pairs and unwrapping session keys.
 */
namespace KeyPairUtils
{
    /**
     * @brief Generates a new X25519 keypair and prints the Base64 strings to the console.
     * Use these strings to update your config.hpp or Python config.py.
     */
    void generate_x25519_keypair()
    {
        unsigned char pk[32], sk[32];
        crypto_box_keypair(pk, sk);

        auto to_b64 = [](const unsigned char *data, size_t len)
        {
            size_t b64_len = sodium_base64_encoded_len(len, sodium_base64_VARIANT_ORIGINAL);
            std::vector<char> b64_out(b64_len);
            sodium_bin2base64(b64_out.data(), b64_out.size(), data, len, sodium_base64_VARIANT_ORIGINAL);
            return std::string(b64_out.data());
        };

        std::string pub_b64 = to_b64(pk, 32);
        std::string priv_b64 = to_b64(sk, 32);

        // Strings matched to keypair_utils.py: generate_keys_action()
        std::cout << "\n--- NEW KEYPAIR GENERATED ---\n";
        std::cout << "PUBLIC KEY (Base64):  " << pub_b64 << "\n";
        std::cout << "PRIVATE KEY (Base64): " << priv_b64 << "\n";
        std::cout << "-----------------------------\n\n";
        std::cout << "Copy these strings to your config.py and config.hpp files.\n";
    }

    /**
     * @brief Unwraps a session key from a file using the local private key.
     * Overwrites the file with the decrypted Base64 session key.
     */
    void decrypt_wrapped_key_action()
    {
        try
        {
            std::ifstream ifs(Config::EWK_FILENAME);
            if (!ifs)
            {
                // String matched to keypair_utils.py: decrypt_wrapped_key()
                std::cerr << "[-] Error: " << Config::EWK_FILENAME << " not found.\n";
                return;
            }

            std::string b64_pkg((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());
            ifs.close();

            // String matched to keypair_utils.py: decrypt_wrapped_key()
            std::cout << "[>] Unwrapping session key...\n";

            unsigned char raw_priv[32];
            size_t bin_len;
            if (sodium_base642bin(raw_priv, 32, Config::PRIVATE_KEY_B64.c_str(), Config::PRIVATE_KEY_B64.length(), NULL, &bin_len, NULL, sodium_base64_VARIANT_ORIGINAL) != 0)
                throw std::runtime_error("Invalid PRIVATE_KEY_B64 in config.hpp");

            auto symkey = CryptoCore::decrypt_symkey_x25519(b64_pkg, raw_priv);

            size_t b64_len = sodium_base64_encoded_len(symkey.size(), sodium_base64_VARIANT_ORIGINAL);
            std::vector<char> b64_out(b64_len);
            sodium_bin2base64(b64_out.data(), b64_out.size(), symkey.data(), symkey.size(), sodium_base64_VARIANT_ORIGINAL);

            std::ofstream ofs(Config::EWK_FILENAME, std::ios::trunc);
            ofs << b64_out.data();

            // String matched to keypair_utils.py: decrypt_wrapped_key()
            std::cout << "[+] Success: Session key unwrapped and saved to disk.\n";
        }
        catch (const std::exception &e)
        {
            std::cerr << "[-] Unwrap failed: " << e.what() << "\n";
        }
    }
}