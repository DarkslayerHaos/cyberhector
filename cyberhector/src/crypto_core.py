import base64, os
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from nacl.bindings import (
    crypto_aead_xchacha20poly1305_ietf_encrypt,
    crypto_aead_xchacha20poly1305_ietf_decrypt
)
from cryptography.hazmat.primitives import serialization
from src.config import MAGIC, INFO, VERSION

def _zeroize_bytes(data: bytes):
    """Zeroizes a bytes object by overwriting its contents in memory (best-effort)."""
    if isinstance(data, (bytes, bytearray)):
        try:
            mv = bytearray(data)
            for i in range(len(mv)):
                mv[i] = 0
        except Exception:
            # Handle immutable types gracefully
            pass

def generate_symkey(length: int = 32) -> bytes:
    """Generates symmetric key (32 bytes by default)."""
    return os.urandom(length)

def wrap_symkey_x25519(symkey: bytes, pub_key: x25519.X25519PublicKey) -> bytes:
    """
    Package (wrap) the symkey using an X25519 public key.
    Returns a base64 package ready to save as 00000000.ewk.

    Internal format (binary):
      MAGIC + VERSION + salt(12) + eph_pub(32) + nonce(24) + ct
    """
    # ephemeral keypair
    eph_priv = x25519.X25519PrivateKey.generate()
    eph_pub = eph_priv.public_key()
    eph_pub_bytes = eph_pub.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )

    # shared secret (ephemeral-static)
    shared = eph_priv.exchange(pub_key)

    # salt (12 bytes)
    salt = os.urandom(12)

    # HKDF-SHA512 derive wrapping key (32 bytes)
    hkdf = HKDF(
        algorithm=hashes.SHA512(),
        length=32,
        salt=salt,
        info=INFO,
    )
    wrapping_key = hkdf.derive(shared)

    # nonce (24 bytes)
    nonce = os.urandom(24)

    # AAD binds to ephemeral context
    aad = MAGIC + VERSION + salt + eph_pub_bytes

    # encrypt the symmetric key
    ct = crypto_aead_xchacha20poly1305_ietf_encrypt(
        symkey,
        aad,
        nonce,
        wrapping_key
    )

    # package: MAGIC | VERSION | salt | eph_pub | nonce | ct
    pkg = MAGIC + VERSION + salt + eph_pub_bytes + nonce + ct

#    best-effort cleanup: Use the dedicated zeroize function
    _zeroize_bytes(shared)
    _zeroize_bytes(wrapping_key)

    return base64.b64encode(pkg)


def encrypt_with_symkey(symkey: bytes, plaintext: bytes) -> bytes:
    """
    Encrypts a block (file) with XChaCha20-Poly1305 and returns a base64 pkg.
    Format: MAGIC + VERSION + nonce(24) + ct
    """
    nonce = os.urandom(24)
    aad = MAGIC + VERSION

    ct = crypto_aead_xchacha20poly1305_ietf_encrypt(
        plaintext,
        aad,
        nonce,
        symkey
    )

    pkg = MAGIC + VERSION + nonce + ct
    return pkg

def decrypt_with_symkey(symkey: bytes, pkg: bytes) -> bytes:
    """
    Decrypts the package created by encrypt_with_symkey.
    """
    data = pkg
    if not data.startswith(MAGIC + VERSION):
        raise ValueError("Invalid magic/version for sym-encrypted file.")
    offset = len(MAGIC) + len(VERSION)

    nonce = data[offset: offset + 24]; offset += 24
    ct = data[offset:]
    aad = MAGIC + VERSION

    pt = crypto_aead_xchacha20poly1305_ietf_decrypt(
        ct,
        aad,
        nonce,
        symkey
    )
    return pt