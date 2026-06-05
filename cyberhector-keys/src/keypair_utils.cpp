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
     * @brief Generates a new X25519 keypair and saves the Base64 strings to files.
     */
    void generate_x25519_keypair()
    {
        unsigned char pk[32], sk[32];
        crypto_box_keypair(pk, sk); //

        auto to_b64 = [](const unsigned char *data, size_t len)
        {
            size_t b64_len = sodium_base64_encoded_len(len, sodium_base64_VARIANT_ORIGINAL);
            std::vector<char> b64_out(b64_len);
            sodium_bin2base64(b64_out.data(), b64_out.size(), data, len, sodium_base64_VARIANT_ORIGINAL);
            return std::string(b64_out.data());
        };

        std::string pub_b64 = to_b64(pk, 32);
        std::string priv_b64 = to_b64(sk, 32);

        // Save public key to file
        std::ofstream pub_file(Config::PUBLIC_KEY_FILENAME, std::ios::trunc);
        if (!pub_file.is_open())
        {
            std::cerr << "[-] Error: Could not create public key file.\n";
            return;
        }
        pub_file << pub_b64;
        pub_file.close();

        // Save private key to file
        std::ofstream priv_file(Config::PRIVATE_KEY_FILENAME, std::ios::trunc);
        if (!priv_file.is_open())
        {
            std::cerr << "[-] Error: Could not create private key file.\n";
            return;
        }
        priv_file << priv_b64;
        priv_file.close();

        std::cout << "\n--- NEW KEYPAIR GENERATED AND SAVED ---\n";
        std::cout << "[+] Public key saved to:  " << Config::PUBLIC_KEY_FILENAME << "\n";
        std::cout << "[+] Private key saved to: " << Config::PRIVATE_KEY_FILENAME << "\n";
        std::cout << "---------------------------------------\n\n";
    }

    /**
     * @brief Unwraps a session key from a file using the local private key file.
     * Overwrites the file with the decrypted Base64 session key.
     */
    void decrypt_wrapped_key_action()
    {
        try
        {
            // Read wrapped key capsule
            std::ifstream ifs(Config::EWK_FILENAME);
            if (!ifs)
            {
                std::cerr << "[-] Error: " << Config::EWK_FILENAME << " not found.\n";
                return;
            }
            std::string b64_pkg((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());
            ifs.close();

            // Read private key from file instead of configuration constants
            std::ifstream priv_file(Config::PRIVATE_KEY_FILENAME);
            if (!priv_file)
            {
                std::cerr << "[-] Error: Private key file (" << Config::PRIVATE_KEY_FILENAME << ") not found.\n";
                return;
            }
            std::string priv_key_b64((std::istreambuf_iterator<char>(priv_file)), std::istreambuf_iterator<char>());
            priv_file.close();

            std::cout << "[>] Unwrapping session key...\n";

            unsigned char raw_priv[32];
            size_t bin_len;
            if (sodium_base642bin(raw_priv, 32, priv_key_b64.c_str(), priv_key_b64.length(), NULL, &bin_len, NULL, sodium_base64_VARIANT_ORIGINAL) != 0)
                throw std::runtime_error("Invalid Base64 string in private key file");

            auto symkey = CryptoCore::decrypt_symkey_x25519(b64_pkg, raw_priv);

            size_t b64_len = sodium_base64_encoded_len(symkey.size(), sodium_base64_VARIANT_ORIGINAL);
            std::vector<char> b64_out(b64_len);
            sodium_bin2base64(b64_out.data(), b64_out.size(), symkey.data(), symkey.size(), sodium_base64_VARIANT_ORIGINAL);

            std::ofstream ofs(Config::EWK_FILENAME, std::ios::trunc);
            ofs << b64_out.data();

            // Securely wipe sensitive materials from memory
            sodium_memzero(raw_priv, sizeof(raw_priv));

            std::cout << "[+] Success: Session key unwrapped and saved to disk.\n";
        }
        catch (const std::exception &e)
        {
            std::cerr << "[-] Unwrap failed: " << e.what() << "\n";
        }
    }
}