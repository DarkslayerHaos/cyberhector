/**
 * @file keypair_utils.cpp
 * @brief Utilities for managing ML-KEM keypairs using PEM format and session key unwrapping.
 */

#include <iostream>
#include <fstream>
#include <vector>
#include <sodium.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include "config.hpp"

namespace CryptoCore
{
    /** @brief Decrypts a Base64-encoded package using a ML-KEM PEM private key file.*/
    std::vector<unsigned char> decrypt_symkey_ml_kem(const std::string &b64_pkg, const std::string &pem_priv_key);
}

namespace KeyPairUtils
{
    /**
     * @brief Generates a new ML-KEM keypair using OpenSSL 3.6 and saves them as PEM files.
     */
    void generate_ml_kem_keypair()
    {
        EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(nullptr, Config::KEM_ALGORITHM.c_str(), nullptr);
        if (!ctx || EVP_PKEY_keygen_init(ctx) <= 0)
        {
            std::cerr << "[-] Error: Could not initialize OpenSSL KEM context.\n";
            if (ctx)
                EVP_PKEY_CTX_free(ctx);
            return;
        }

        EVP_PKEY *pkey = nullptr;
        if (EVP_PKEY_keygen(ctx, &pkey) <= 0)
        {
            std::cerr << "[-] Error: ML-KEM key generation failed.\n";
            EVP_PKEY_CTX_free(ctx);
            return;
        }

        // Save public key to file in PEM format
        BIO *pub_bio = BIO_new_file(Config::PUBLIC_KEY_FILENAME.c_str(), "w");
        if (!pub_bio)
        {
            std::cerr << "[-] Error: Could not create public key file.\n";
            EVP_PKEY_free(pkey);
            EVP_PKEY_CTX_free(ctx);
            return;
        }
        PEM_write_bio_PUBKEY(pub_bio, pkey);
        BIO_free(pub_bio);

        // Save private key to file in PEM format (unencrypted PKCS#8)
        BIO *priv_bio = BIO_new_file(Config::PRIVATE_KEY_FILENAME.c_str(), "w");
        if (!priv_bio)
        {
            std::cerr << "[-] Error: Could not create private key file.\n";
            EVP_PKEY_free(pkey);
            EVP_PKEY_CTX_free(ctx);
            return;
        }
        PEM_write_bio_PrivateKey(priv_bio, pkey, nullptr, nullptr, 0, nullptr, nullptr);
        BIO_free(priv_bio);

        // Clean OpenSSL structs
        EVP_PKEY_free(pkey);
        EVP_PKEY_CTX_free(ctx);

        std::cout << "\n--- NEW KYBER1024 PEM KEYPAIR GENERATED AND SAVED ---\n";
        std::cout << "[+] Public key saved to (PEM):  " << Config::PUBLIC_KEY_FILENAME << "\n";
        std::cout << "[+] Private key saved to (PEM): " << Config::PRIVATE_KEY_FILENAME << "\n";
        std::cout << "-----------------------------------------------------\n\n";
    }

    /**
     * @brief Unwraps a session key from a file using the local ML-KEM PEM private key file.
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

            // Read private key file content directly as PEM string
            std::ifstream priv_file(Config::PRIVATE_KEY_FILENAME);
            if (!priv_file)
            {
                std::cerr << "[-] Error: Private key file (" << Config::PRIVATE_KEY_FILENAME << ") not found.\n";
                return;
            }
            std::string priv_key_pem((std::istreambuf_iterator<char>(priv_file)), std::istreambuf_iterator<char>());
            priv_file.close();

            std::cout << "[>] Unwrapping session key via ML-KEM (PEM mode)...\n";

            auto symkey = CryptoCore::decrypt_symkey_ml_kem(b64_pkg, priv_key_pem);
            
            size_t b64_len = sodium_base64_encoded_len(symkey.size(), sodium_base64_VARIANT_ORIGINAL);
            
            std::vector<char> b64_out(b64_len);
            sodium_bin2base64(b64_out.data(), b64_out.size(), symkey.data(), symkey.size(), sodium_base64_VARIANT_ORIGINAL);
            
            sodium_memzero(symkey.data(), symkey.size());
            
            std::ofstream ofs(Config::EWK_FILENAME, std::ios::trunc);
            ofs << b64_out.data();

            sodium_memzero(b64_out.data(), b64_out.size());

            std::cout << "[+] Success: Session key unwrapped and saved to disk.\n";
        }
        catch (const std::exception &e)
        {
            std::cerr << "[-] Unwrap failed: " << e.what() << "\n";
        }
    }
}