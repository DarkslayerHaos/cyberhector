# Final executable name
TARGET = cyberhector.exe

# Source files required for the main encryption/decryption logic
SRCS = main.cpp crypto_core.cpp file_ops.cpp

# Compiler settings
# -std=c++17: Language standard
# -Wall -Wextra: Enable all common and extra warnings for safer code
# -O3: Maximum optimization for cryptographic performance
CXX = g++
CXXFLAGS = -std=c++17 -Wall -Wextra -O3

# External libraries
# -lsodium: Required for XChaCha20 and X25519 primitives
LIBS = -lsodium

# Default target: Compiles the entire project
all:
	@echo "[!] Building $(TARGET)..."
	$(CXX) $(SRCS) -o $(TARGET) $(CXXFLAGS) $(LIBS)
	@echo "[+] Build successful."

# Clean target: Removes the executable to force a fresh build
clean:
	@echo "[!] Cleaning workspace..."
	if exist $(TARGET) del $(TARGET)
	@echo "[+] Workspace cleaned."

.PHONY: all clean