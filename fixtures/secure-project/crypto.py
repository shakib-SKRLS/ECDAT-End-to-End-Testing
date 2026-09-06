"""Secure cryptographic operations."""
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import hashlib


def encrypt_aes_256(key: bytes, iv: bytes, plaintext: bytes):
    """AES-256-GCM - modern AEAD."""
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv))
    encryptor = cipher.encryptor()
    return encryptor.update(plaintext) + encryptor.finalize()


def encrypt_chacha20(key: bytes, nonce: bytes, plaintext: bytes):
    """ChaCha20-Poly1305 - modern AEAD."""
    cipher = Cipher(algorithms.ChaCha20(key), modes.Poly1305(nonce))
    encryptor = cipher.encryptor()
    return encryptor.update(plaintext) + encryptor.finalize()


def hash_sha256(data: bytes) -> str:
    """SHA-256 - secure hash function."""
    return hashlib.sha256(data).hexdigest()


def hash_sha384(data: bytes) -> str:
    """SHA-384 - stronger hash for long-term security."""
    return hashlib.sha384(data).hexdigest()


def derive_key_pbkdf2(password: str, salt: bytes):
    """PBKDF2 with SHA-256 - secure KDF."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=480000,
    )
    return kdf.derive(password.encode())
