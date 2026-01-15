/**
 * @file main.cpp
 * @brief Entry point for file encryption and decryption operations.
 */

#include <iostream>
#include <vector>
#include <string>
#include <sodium.h>
#include <filesystem>
#include "src/config.hpp"

namespace fs = std::filesystem;

/**
 * Forward declarations for cryptographic core functions.
 * Implementation resides in crypto_core.cpp
 */
namespace CryptoCore
{
    std::vector<unsigned char> generate_symkey();
    std::string wrap_symkey(const std::vector<unsigned char> &symkey);
}

/**
 * Forward declarations for file system operations.
 * Implementation resides in file_ops.cpp
 */
namespace FileOps
{
    void process_encryption(const std::vector<unsigned char> &symkey);
    void process_decryption(const std::vector<unsigned char> &symkey);
    void write_file(const std::filesystem::path &path, const std::string &data);
    std::string read_file_as_string(const fs::path &path);
}

int main()
{
    // Initialize libsodium for secure random generation and primitives
    if (sodium_init() < 0)
    {
        std::cerr << "Critical Error: Sodium initialization failed!\n";
        return 1;
    }

    std::cout << "\n--- CyberHector File Encryption Utility ---\n";
    std::cout << "[1] Encrypt files (Generates " << Config::EWK_FILENAME << ")\n";
    std::cout << "[2] Decrypt files (Requires unwrapped " << Config::EWK_FILENAME << ")\n";
    std::cout << "Select an option: ";

    std::string choice;
    std::getline(std::cin, choice);

    try
    {
        if (choice == "1")
        {
            /**
             * ENCRYPTION FLOW:
             * 1. Generate a high-entropy 32-byte master session key.
             * 2. Wrap (Encapsulate) this key using X25519 (Recipient's Public Key).
             * 3. Save the capsule to disk and process all files in the target directory.
             */
            std::cout << "\n[>] Generating session keys..." << std::endl;
            auto master_key = CryptoCore::generate_symkey();

            std::string wrapped_b64 = CryptoCore::wrap_symkey(master_key);
            FileOps::write_file(Config::EWK_FILENAME, wrapped_b64);

            std::cout << "[+] Key capsule saved to " << Config::EWK_FILENAME << "\n";
            FileOps::process_encryption(master_key);

            // SECURITY: Wipe the symmetric key from RAM immediately after use
            sodium_memzero(master_key.data(), master_key.size());
            std::cout << "[!] Memory wiped. Encryption process finished.\n";
        }
        else if (choice == "2")
        {
            /**
             * DECRYPTION FLOW:
             * 1. Read the .ewk file (must be unwrapped by the Key Utility first).
             * 2. Decode the Base64 key into raw bytes.
             * 3. Use the recovered key to decrypt file contents.
             */
            if (!fs::exists(Config::EWK_FILENAME))
                throw std::runtime_error("Key capsule file (" + Config::EWK_FILENAME + ") missing!");

            std::cout << "\n[>] Reading session key from capsule..." << std::endl;
            std::string b64_key = FileOps::read_file_as_string(Config::EWK_FILENAME);

            // Buffer for the raw 32-byte key
            std::vector<unsigned char> master_key(32);
            size_t decoded_len;

            // Decode the "unwrapped" key back to binary
            if (sodium_base642bin(master_key.data(), master_key.size(), b64_key.c_str(), b64_key.length(),
                                  NULL, &decoded_len, NULL, sodium_base64_VARIANT_ORIGINAL) != 0)
            {
                sodium_memzero(master_key.data(), master_key.size());
                throw std::runtime_error("Failed to decode key: Check if the .ewk was properly unwrapped.");
            }

            FileOps::process_decryption(master_key);

            // SECURITY: Wipe the recovered key from RAM
            sodium_memzero(master_key.data(), master_key.size());
            std::cout << "[!] Memory wiped. Decryption process finished.\n";
        }
        else
        {
            std::cout << "Invalid selection. Exiting.\n";
        }
    }
    catch (const std::exception &e)
    {
        std::cerr << "\n[-] FATAL ERROR: " << e.what() << "\n";
        return 1;
    }

    return 0;
}