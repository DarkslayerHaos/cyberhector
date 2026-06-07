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

    // Key storage file names
    const std::string PUBLIC_KEY_FILENAME = "cyberhector.pub";
    const std::string PRIVATE_KEY_FILENAME = "cyberhector.key";
    
    // Crypto constants (Protocol Sync)
    const std::string INFO = "CyberHector-PQC";
    const std::string MAGIC = "HECSPEC1";
    const unsigned char VERSION = 0x01;

    // OpenSSL Alg Name for ML-KEM
    const std::string KEM_ALGORITHM = "ML-KEM-768";
}

#endif