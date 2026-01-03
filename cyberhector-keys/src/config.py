from pathlib import Path

# --- File names / paths ---
EWK_FILENAME = "00000000.ewk"
EWK_PATH = Path(EWK_FILENAME)

# --- Crypto constants (Protocol Sync) ---
MAGIC = b"HECSPEC0"
VERSION = b"\x01"
INFO = b"CyberHector-KeyDerivation"

# --- Master Private Key (Direct Base64 String) ---
# Paste the string here. The C++ project will use this same string.
PRIVATE_KEY_B64 = ""