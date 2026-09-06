"""Vulnerable authentication module with weak cryptography."""
import hashlib
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes


def generate_rsa_1024():
    """Generate RSA-1024 key - weak key size."""
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=1024,
    )


def generate_rsa_2048():
    """Generate RSA-2048 key - quantum vulnerable."""
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )


def hash_password_md5(password: str) -> str:
    """MD5 password hashing - broken."""
    return hashlib.md5(password.encode()).hexdigest()


def hash_password_sha1(password: str) -> str:
    """SHA-1 password hashing - deprecated."""
    return hashlib.sha1(password.encode()).hexdigest()


def sign_with_sha1(data: bytes):
    """SHA-1 signature - collision broken."""
    return hashlib.sha1(data).hexdigest()
