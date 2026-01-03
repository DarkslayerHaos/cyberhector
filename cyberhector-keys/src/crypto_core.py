import base64
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from nacl.bindings import crypto_aead_xchacha20poly1305_ietf_decrypt
from .config import MAGIC, VERSION, INFO

def _zeroize_bytes(data: bytes):
    """Zeroizes a bytes object by overwriting its contents in memory (best-effort)."""
    if isinstance(data, (bytes, bytearray)):
        try:
            mv = bytearray(data)
            # Overwrite the contents with zeros
            for i in range(len(mv)):
                mv[i] = 0
        except Exception:
            # Handle immutable types gracefully
            pass

def decrypt_symkey_x25519(private_key: x25519.X25519PrivateKey, b64pkg: bytes) -> bytes:
    """
    Unwrap symmetric key from the package created by wrap_symkey_x25519.

    Expected internal binary format:
      MAGIC + VERSION + salt (12) + eph_pub(32) + nonce(24) + ct
    """
    data = base64.b64decode(b64pkg)

    # minimal length check: magic + version + salt + eph_pub + kid + nonce + at least tag
    min_len = len(MAGIC) + len(VERSION) + 12 + 32 + 24 + 16  # 16 = AEAD tag min
    if len(data) < min_len:
        raise ValueError("Package too short or truncated")

    # magic + version check
    if not data.startswith(MAGIC + VERSION):
        raise ValueError("Invalid magic/version")

    offset = len(MAGIC) + len(VERSION)

    # salt (12 bytes)
    salt = data[offset: offset + 12]
    offset += 12

    # ephemeral pub (X25519 = 32 bytes)
    eph_pub_bytes = data[offset: offset + 32]
    try:
        eph_pub = x25519.X25519PublicKey.from_public_bytes(eph_pub_bytes)
    except Exception as e:
        raise ValueError("Invalid ephemeral public key bytes") from e
    offset += 32

    # nonce (24 bytes)
    nonce = data[offset: offset + 24]
    offset += 24

    # ciphertext (rest)
    ct = data[offset:]
    if len(ct) < 16:
        raise ValueError("Ciphertext too short (missing AEAD tag)")

    # DH shared secret (ephemeral-static)
    shared = private_key.exchange(eph_pub)

    # HKDF-SHA512 (must match wrap function)
    hkdf = HKDF(
        algorithm=hashes.SHA512(),
        length=32,
        salt=salt,
        info=INFO,
    )
    wrapping_key = hkdf.derive(shared)

    # AAD: MAGIC + VERSION + salt + eph_pub
    aad = MAGIC + VERSION + salt + eph_pub_bytes

    # decrypt (propagate a clear error on auth failure)
    try:
        pt = crypto_aead_xchacha20poly1305_ietf_decrypt(
            ct,
            aad,
            nonce,
            wrapping_key
        )
    except Exception as e:
        # Better error message for auth failure / tampering
        raise ValueError("Decryption failed (authentication error or wrong key)") from e

    # best-effort cleanup of sensitive material
    _zeroize_bytes(shared)
    _zeroize_bytes(wrapping_key)
    
    return pt