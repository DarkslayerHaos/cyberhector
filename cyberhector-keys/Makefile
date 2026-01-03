# Final executable name
TARGET = key_util.exe

# Source files required for key unwrapping and generation
SRCS = main.cpp crypto_core.cpp keypair_utils.cpp

# Compiler settings
CXX = g++
CXXFLAGS = -std=c++17 -Wall -Wextra -O3

# External libraries
LIBS = -lsodium

# Default target: Compiles the key utility
all:
	@echo "[!] Building $(TARGET)..."
	$(CXX) $(SRCS) -o $(TARGET) $(CXXFLAGS) $(LIBS)
	@echo "[+] Build successful."

# Clean target: Removes the utility executable
clean:
	@echo "[!] Cleaning workspace..."
	if exist $(TARGET) del $(TARGET)
	@echo "[+] Workspace cleaned."

.PHONY: all clean