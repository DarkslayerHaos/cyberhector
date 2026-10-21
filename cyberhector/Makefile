# Final executable name
TARGET = cyberhector.exe

# Source files
SRCS = main.cpp src/crypto_core.cpp src/file_ops.cpp

# Compiler settings
CXX = g++

# --- PROTECTION & OPTIMIZATION SETTINGS ---

# Basic flags and Libsodium static support
CXXFLAGS = -std=c++20 -Wall -Wextra -O3 -DSODIUM_STATIC

# Aggressive Anti-Reversing & Optimization
CXXFLAGS += \
	-fomit-frame-pointer \
	-fno-unwind-tables \
	-fipa-pta \
	-fvisibility=hidden \
	-fstack-protector-strong

# Linker flags for a stripped, standalone binary
LDFLAGS = -static -static-libgcc -static-libstdc++ \
          -Wl,--gc-sections \
          -Wl,--strip-all

# External libraries
LIBS = -lssl -lsodium -lcrypto -lws2_32 -lcrypt32 -lpthread

# --- BUILD TARGETS ---

all:
	@echo "[!] Building standalone $(TARGET)..."
	$(CXX) $(SRCS) -o $(TARGET) $(CXXFLAGS) $(LDFLAGS) $(LIBS)
	@echo "[+] Build successful."

.PHONY: all