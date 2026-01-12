# Final executable name
TARGET = cyberhector.exe

# Source files
SRCS = main.cpp crypto_core.cpp file_ops.cpp

# Compiler settings
CXX = g++

# CXXFLAGS updates:
# -DSODIUM_STATIC: Required when linking libsodium statically
# -static: Tells the linker to link all libraries statically (no DLL dependencies)
# -static-libgcc -static-libstdc++: Specifically ensures C/C++ runtimes are embedded
CXXFLAGS = -std=c++17 -Wall -Wextra -O3 -DSODIUM_STATIC -static -static-libgcc -static-libstdc++ -s

# External libraries
# The linker will now look for libsodium.a instead of libsodium.dll.a due to the -static flag
LIBS = -lsodium -lpthread

# Default target
all:
	@echo "[!] Building standalone $(TARGET)..."
	$(CXX) $(SRCS) -o $(TARGET) $(CXXFLAGS) $(LIBS)
	@echo "[+] Build successful."

# Clean target
clean:
	@echo "[!] Cleaning workspace..."
	if exist $(TARGET) del $(TARGET)
	@echo "[+] Workspace cleaned."

.PHONY: all clean