"""Vulnerable cryptographic operations."""
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import ec
import hashlib


def encrypt_aes_128(key: bytes, iv: bytes, plaintext: bytes):
    """AES-128 - consider upgrading to 256 for long-term security."""
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    return encryptor.update(plaintext) + encryptor.finalize()


def encrypt_3des(key: bytes, iv: bytes, plaintext: bytes):
    """3DES - deprecated symmetric cipher."""
    from cryptography.hazmat.primitives.ciphers.algorithms import TripleDES
    cipher = Cipher(TripleDES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    return encryptor.update(plaintext) + encryptor.finalize()


def generate_ecdsa():
    """ECDSA - quantum vulnerable."""
    return ec.generate_private_key(ec.SECP256R1())


def generate_ecdh():
    """ECDH - quantum vulnerable key exchange."""
    return ec.generate_private_key(ec.SECP256R1())


def hash_md5(data: bytes) -> str:
    """MD5 - cryptographically broken."""
    return hashlib.md5(data).hexdigest()


def hash_sha1(data: bytes) -> str:
    """SHA-1 - collision broken."""
    return hashlib.sha1(data).hexdigest()
