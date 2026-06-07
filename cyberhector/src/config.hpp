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
    const std::string KEM_ALGORITHM = "ML-KEM-768";

    /**
     * ML-KEM-768 Public Key (PEM String Format).
     * Replace the string representation below with your actual generated PEM public key block.
     */
    const std::string PUBLIC_KEY_PEM = R"(-----BEGIN PUBLIC KEY-----
MIIEsjALBglghkgBZQMEBAIDggShADMSE8jxy4xwmj9hCaGlJMSzQvjaa13RbEAp
M/j4pXcYWMkCtduwlBFoyBhnwFoVwQ50sl/pNEWIFzNxxV0ZwYCmyoupE4D8p0dU
Oc6gtlXDBUf4PjlyPRMkB0YoSA72NMdlYjvAgdh7NsAcmhV5d7wQkr1LUZognCtl
aWh3HN+6vwWGwrtTfs+mJfBDYJUxtvfyeF8sw0QUM4cqzmKclh08pJdFFFr1g2Ig
wGvWK+q2BUzoBVFLP6n7QTFimszgkc9TLVXxyvjlZh18nZ1RmXLUKdAcNI0WqAIl
npvnb8+hnKkkBocH0LpQAeHhX3e5txyZtD88rXYWspc3poP2wzu3LTzQWoTDPMj8
r073p74xZw+UQnwWrWJzfEnaCFWoCrWis3KMtcy2ULm3p8ojl5/EM2LLXK11NLCx
FiCJK0ScUNBpzo68yTfEzpASwfcMCZd1W6MGBeoLuzwzgFeVItrTP835tDtkEq74
CLQCNIg1F7gqNH8KQZSDqwrRl/vpLmtKQPchfO50UBgRTIHhnmqjEnBsUdrWmVry
xI0XRAZFKyS0qohgT5o3hmqUqFJFADRME26sIOaZiKVnDP7yHPHkYPXDnsv2JCyI
sTZrdCChD50TOPnzyRQqS5zLHlL3pmE2BQ+MSPZYI5XTorO6EO4DEVYjRicqedqR
onVFpsW2NHqsiDO5I5ysRHg0jc8rmOyCNAnIi8x6dvTwDaLsVTSbG5q0FZn0Q512
hXalxMSpxu5UWDhLBEnYlUlIGYMYDfYrYowCcKWXc11gh+IsyQY6N0SnQa73Z77I
c4oAQlRXztujOPPlFTczy7UyR+H2gLFVDHwQfM8LxkkKgR64mvlXA9AVcgyqbf53
a+HbVDkZHAxpUiZXwOUyOyTFeF2idg0GBpjCjvkEEDUFYqvFe5xCsN2MXOiVvd1y
LfyLVTS2Ol6abacSXCNnUe9rUBUDnb7GM4KbcpsCz5iQD8IYukkckP4rQT6ZkQgl
E9p0eLdBiyVDjVxSwyc0VudbOZCGEGryEcL7fHrxabIQWvaUsNz3bNOMQvXsFaqK
vfkrLENXV94WTHc6y8EyWNJLz1m4OanJWALyJuNcs8lkRHgVDku3TX4cnBasSlvT
teNDA7LhXmKJsT+AJhJKnClFRM55ZxRlYbtWkAG3Jo9nx6jLCsL0wTV7xYoJwdbF
beeUeE7xOH/YqE4Kfs8mECGLlHPXBjVglQALAzo0Mqv0F7fHPu4UoR3AAciRGq5w
e0AnsIRbxbv4McQ6I3P1oIqIIk2aCBFhdxvGMC78YaKkoRkGBHN1FfEsIMrQQYtp
vhtiBuq8AQJ8vhPyOBoJeetnaHciE+nSK27oVEMoBBasy+GrYuQ8RbdyiaxjT3OS
icdwzK06kY8oIDeoouzJOW6aM7s8HTOruVR0DqFDaT3gNC4DYflbb6cLfkO6e0YQ
IJWMF5rCCMrHzy5nwI1iru4mANDsq2mSAzA0REJcmfEqbm0zu8wbZ29cJrfJFZUp
W8GilFuEew0yJ8JJPgzqTcLGSlz7EQvK1MgSuvg4iajUpwUWQ67kl4YpKWvOFBuO
qMo065tY
-----END PUBLIC KEY-----)";
}

#endif