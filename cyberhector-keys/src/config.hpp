/**
 * @file config.hpp
 * @brief Security-critical configuration.
 */

#ifndef CONFIG_KEYS_HPP
#define CONFIG_KEYS_HPP

#include <string>

/**
 * @namespace Config
 * @brief Global settings for file extensions, crypto headers, and public keys.
 */
namespace Config
{
    // File names / paths
    const std::string EWK_FILENAME = "00000000.ewk";

    // Crypto constants (Protocol Sync)
    const std::string MAGIC = "HECSPEC0";
    const unsigned char VERSION = 0x01;
    const std::string INFO = "CyberHector-KeyDerivation";

    /**
     * X25519 Private Key (Base64 String).
     * Used for the Key Encapsulation Mechanism (KEM) to unwrap session keys.
     */
    const std::string PRIVATE_KEY_B64 = "";
}

#endif