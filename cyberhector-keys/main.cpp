/**
 * @file main.cpp
 * @brief Entry point for the CyberHector Key Utility (ML-KEM Migration).
 */

#include <iostream>
#include <string>
#include <sodium.h>

// Forward declarations
namespace KeyPairUtils
{
    /** @brief Generates and displays a new ML-KEM keypair. */
    void generate_ml_kem_keypair();
    /** @brief Decrypts the session key file using the configured Kyber private key. */
    void decrypt_wrapped_key_action();
}

int main()
{
    if (sodium_init() < 0)
        return 1;

    std::cout << "\n--- CyberHector Key Utility ---\n";
    std::cout << "[1] Unwrap Key Capsule (Decrypts .ewk)\n";
    std::cout << "[2] Generate New ML-KEM Key Pair\n";

    std::cout << "Select an option: ";
    std::string choice;
    std::getline(std::cin, choice);

    if (!choice.empty() && choice.back() == '\r')
        choice.pop_back();

    if (choice == "1")
    {
        KeyPairUtils::decrypt_wrapped_key_action();
    }
    else if (choice == "2")
    {
        KeyPairUtils::generate_ml_kem_keypair();
    }
    else
    {
        std::cout << "Invalid option.\n";
    }

    return 0;
}