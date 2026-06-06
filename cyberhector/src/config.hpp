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
    const bool REMOVE_ORIGINAL_FILES = false;
    
    // Crypto Metadata (Header)
    const std::string INFO = "CyberHector-KeyDerivation";
    const std::string MAGIC = "HECSPEC0";
    const unsigned char VERSION = 0x01;
    
    // Maximum file size allowed for encryption/decryption (20 GB).
    const unsigned long long MAX_FILE_SIZE_BYTES = 20ULL * 1024 * 1024 * 1024;
    
    /**
     * X25519 Public Key (Base64 String).
     * Used for the Key Encapsulation Mechanism (KEM) to wrap session keys.
     */
    const std::string PUBLIC_KEY_B64 = "SYENy0AaAIsh0J0Z3vVI9tCiyrds2wFZXrrfxNIYhWM=";
}

#endif