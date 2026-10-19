/**
 * @file config.hpp
 * @brief Global configuration constants for the CyberHector File Utility.
 */

#ifndef CONFIG_HPP
#define CONFIG_HPP

#include <string>

/**
 * @namespace Config
 * @brief Global settings for file extensions, crypto headers, and public keys.
 */
namespace Config
{
    // File System Settings
    const std::string FILE_EXTENSION = ".cybr";
    const std::string EWK_FILENAME = "00000000.ewk";
    const std::string TARGET_DIR = "Private Folder";
    const bool REMOVE_ORIGINAL_FILES = true;

    // Crypto Metadata (Header)
    const std::string INFO = "CyberHector-PQC";
    const std::string MAGIC = "HECSPEC1";
    const unsigned char VERSION = 0x01;

    // Maximum file size allowed for encryption/decryption (20 GB).
    const unsigned long long MAX_FILE_SIZE_BYTES = 20ULL * 1024 * 1024 * 1024;

    // OpenSSL Alg Name for ML-KEM
    const std::string KEM_ALGORITHM = "ML-KEM-1024";

    /**
     * ML-KEM-1024 Public Key (PEM String Format).
     * Replace the string representation below with your actual generated PEM public key block.
     */
    const std::string PUBLIC_KEY_PEM = R"(-----BEGIN PUBLIC KEY-----
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
hTxfaAot
-----END PUBLIC KEY-----)";
}

#endif