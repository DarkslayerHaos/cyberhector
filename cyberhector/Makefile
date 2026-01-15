# Final executable name
TARGET = cyberhector.exe

# Source files
SRCS = main.cpp src/crypto_core.cpp src/file_ops.cpp

# Compiler settings
CXX = g++

# --- PROTECTION & OPTIMIZATION SETTINGS ---

# Basic flags and Libsodium static support
CXXFLAGS = -std=c++17 -Wall -Wextra -O3 -DSODIUM_STATIC

# Aggressive Anti-Reversing & Optimization
# These flags hinder code flow analysis and remove metadata 
CXXFLAGS += \
	-fomit-frame-pointer \
	-fno-unwind-tables \
	-finline-functions \
	-finline-small-functions \
	-fipa-pta \
	-fipa-cp \
	-fipa-sra \
	-fvisibility=hidden

# Linker flags for a stripped, standalone binary
# -Wl,--gc-sections: Removes unused code
# -Wl,--strip-all: Removes all symbols and debug info
LDFLAGS = -static -static-libgcc -static-libstdc++ \
          -Wl,--gc-sections \
          -Wl,--strip-all \
          -s 

# External libraries
LIBS = -lsodium -lpthread

# --- BUILD TARGETS ---

all:
	@echo "[!] Building standalone $(TARGET)..."
	$(CXX) $(SRCS) -o $(TARGET) $(CXXFLAGS) $(LDFLAGS) $(LIBS)
	@echo "[+] Build successful."

clean:
	@echo "[!] Cleaning workspace..."
	@if exist $(TARGET) del $(TARGET) [cite: 2]
	@echo "[+] Workspace cleaned."

.PHONY: all clean