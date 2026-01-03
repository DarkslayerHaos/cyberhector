from pathlib import Path

# --- File names / paths ---
FILE_EXTENSION = ".cybr"
EWK_FILENAME = "00000000.ewk"
EWK_PATH = Path(EWK_FILENAME)
TARGET_DIR = Path("Private")

# --- Crypto constants ---
MAGIC = b"HECSPEC0"
VERSION = b"\x01"
INFO = b"CyberHector-KeyDerivation"

# --- Key material (only non-secret stuff here) ---
PUBLIC_KEY_B64 = "SYENy0AaAIsh0J0Z3vVI9tCiyrds2wFZXrrfxNIYhWM="

# --- Behaviour flags ---
REMOVE_ORIGINAL_FILES = True