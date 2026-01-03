@echo off
setlocal enabledelayedexpansion

REM =============================================
REM Build exe for CyberHector (Windows CMD safe)
REM Run this script from the root directory (where the 'cyberhector' folder is located)
REM =============================================

set EXE_NAME=cyberhector

REM =============================================
REM Detect PyNaCl binary (_sodium.pyd)
REM =============================================
echo Detecting libsodium...

for /f "delims=" %%i in ('python -c "import nacl, os; d=os.path.dirname(nacl.__file__); import glob; m=glob.glob(os.path.join(d,'_sodium*.pyd')); print(m[0] if m else '')"') do (
    set SODIUM_BINDING=%%i
)

if not "!SODIUM_BINDING!"=="" (
    echo Found sodium: !SODIUM_BINDING!
    REM Add binary relative to the root build location
    set ADD_BINARY=--add-binary "!SODIUM_BINDING!;."
) else (
    echo WARNING: Could not automatically find _sodium.pyd
    set ADD_BINARY=
)

echo.

REM =============================================
REM PyInstaller command
REM =============================================

pyinstaller --onefile --console --clean ^
 --name %EXE_NAME% ^
 --hidden-import=cryptography.hazmat.primitives.asymmetric.x25519 ^
 --hidden-import=cryptography.hazmat.primitives.serialization ^
 --hidden-import=cryptography.hazmat.primitives.kdf.hkdf ^
 --hidden-import=cryptography.hazmat.primitives.hashes ^
 --hidden-import=nacl.bindings ^
 --hidden-import=nacl.bindings.crypto_aead_xchacha20poly1305_ietf_encrypt ^
 --hidden-import=nacl.bindings.crypto_aead_xchacha20poly1305_ietf_decrypt ^
 --add-data "cyberhector/src;src" ^
 %ADD_BINARY% ^
 cyberhector/main.py

echo.
echo =============================================
echo Build finished. Check the /dist folder.
echo =============================================
pause