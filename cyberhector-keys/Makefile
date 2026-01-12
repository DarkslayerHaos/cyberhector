# Final executable name
TARGET = key_util.exe

# Source files required for key unwrapping and generation
SRCS = main.cpp crypto_core.cpp keypair_utils.cpp

# Compiler settings
CXX = g++

# CXXFLAGS updates:
# -DSODIUM_STATIC: Required for static linking with libsodium
# -static: Links all libraries (including system libs) statically
# -static-libgcc -static-libstdc++: Ensures C++ runtime is embedded
# -s: Strips symbols to significantly reduce file size (around 1.5MB final)
CXXFLAGS = -std=c++17 -Wall -Wextra -O3 -DSODIUM_STATIC -static -static-libgcc -static-libstdc++ -s

# External libraries
# The linker will prioritize libsodium.a over the DLL import library
LIBS = -lsodium -lpthread

# Default target: Compiles the standalone utility
all:
	@echo "[!] Building standalone $(TARGET)..."
	$(CXX) $(SRCS) -o $(TARGET) $(CXXFLAGS) $(LIBS)
	@echo "[+] Build successful."

# Clean target: Removes the utility executable
clean:
	@echo "[!] Cleaning workspace..."
	if exist $(TARGET) del $(TARGET)
	@echo "[+] Workspace cleaned."

.PHONY: all clean