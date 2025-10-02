# crypto_module.py

import os
import base64
import hashlib
from datetime import datetime
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256  # Fixed: PyCryptodome hash module

# Constants
KDF_ITERATIONS = 200_000
KEY_LEN = 32  # AES-256
SALT_SIZE = 16
IV_SIZE = 12  # recommended for GCM

def _sha256_bytes(data: bytes) -> str:
    """Return SHA-256 hex digest of bytes."""
    return hashlib.sha256(data).hexdigest()

def derive_key(password: str, salt: bytes) -> bytes:
    """
    Derive AES key from password and salt using PBKDF2-HMAC-SHA256.
    """
    return PBKDF2(
        password.encode('utf-8'),
        salt,
        dkLen=KEY_LEN,
        count=KDF_ITERATIONS,
        hmac_hash_module=SHA256  # Fixed: use PyCryptodome SHA256
    )

def encrypt_file(input_bytes: bytes, password: str) -> dict:
    """
    Encrypt bytes using AES-256-GCM and password.
    Returns dict containing ciphertext, salt, iv, tag, file_hash, and timestamp.
    """
    salt = get_random_bytes(SALT_SIZE)
    iv = get_random_bytes(IV_SIZE)
    key = derive_key(password, salt)

    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
    ciphertext, tag = cipher.encrypt_and_digest(input_bytes)

    file_hash = _sha256_bytes(input_bytes)
    return {
        "ciphertext": ciphertext,
        "salt": base64.b64encode(salt).decode('utf-8'),
        "iv": base64.b64encode(iv).decode('utf-8'),
        "tag": base64.b64encode(tag).decode('utf-8'),
        "file_hash": file_hash,
        "created_at": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    }

def decrypt_file(ciphertext: bytes, password: str, salt_b64: str, iv_b64: str, tag_b64: str) -> bytes:
    """
    Decrypt AES-256-GCM encrypted bytes using password and metadata.
    Raises ValueError if decryption fails.
    """
    salt = base64.b64decode(salt_b64)
    iv = base64.b64decode(iv_b64)
    tag = base64.b64decode(tag_b64)
    key = derive_key(password, salt)

    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
    try:
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        return plaintext
    except Exception as e:
        raise ValueError("Decryption failed. Wrong password or corrupted file.") from e

def safe_filename_hash(file_bytes: bytes) -> str:
    """Return SHA-256 hex digest to use as encrypted filename base."""
    return hashlib.sha256(file_bytes).hexdigest()


# -------------------------
# Quick Test (Optional)
# -------------------------
if __name__ == "__main__":
    test_data = b"Hello world! This is a test file."
    test_password = "mypassword123"

    print("Encrypting test data...")
    enc = encrypt_file(test_data, test_password)
    print("Ciphertext (bytes):", enc["ciphertext"][:16], "...")  # show first 16 bytes
    print("Salt:", enc["salt"])
    print("IV:", enc["iv"])
    print("Tag:", enc["tag"])
    print("File Hash:", enc["file_hash"])
    print("Created At:", enc["created_at"])

    print("\nDecrypting test data...")
    decrypted = decrypt_file(
        enc["ciphertext"],
        test_password,
        enc["salt"],
        enc["iv"],
        enc["tag"]
    )
    print("Decrypted data:", decrypted)
    assert decrypted == test_data
    print("✅ Encryption & decryption test passed.")
