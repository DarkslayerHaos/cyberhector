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
    const std::string TARGET_DIR = "Private";
    const bool REMOVE_ORIGINAL_FILES = true;

    // Crypto Metadata (Header)
    const std::string MAGIC = "HECSPEC0";
    const unsigned char VERSION = 0x01;
    const std::string INFO = "CyberHector-KeyDerivation";

    /**
     * X25519 Public Key (Base64 String).
     * Used for the Key Encapsulation Mechanism (KEM) to wrap session keys.
     * Paste the Base64 text from your public_key.bin here.
     */
    const std::string PUBLIC_KEY_B64 = "SYENy0AaAIsh0J0Z3vVI9tCiyrds2wFZXrrfxNIYhWM=";
}

#endif