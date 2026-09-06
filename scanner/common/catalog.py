"""Deterministic cryptographic catalog used by detection, risk, and PQC engines."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class AlgorithmProfile:
    name: str
    family: str
    primitive_type: str
    quantum_vulnerable: bool
    baseline_algorithm_risk: int  # 0-40
    notes: str


PROFILES: dict[str, AlgorithmProfile] = {
    "RSA": AlgorithmProfile("RSA", "asymmetric", "public_key", True, 28, "Shor-vulnerable public-key algorithm"),
    "DSA": AlgorithmProfile("DSA", "asymmetric", "digital_signature", True, 30, "Shor-vulnerable signature algorithm"),
    "ECDSA": AlgorithmProfile("ECDSA", "ecc", "digital_signature", True, 26, "Shor-vulnerable ECC signatures"),
    "ECDH": AlgorithmProfile("ECDH", "ecc", "key_establishment", True, 28, "Shor-vulnerable key agreement"),
    "DH": AlgorithmProfile("DH", "asymmetric", "key_establishment", True, 30, "Finite-field Diffie-Hellman"),
    "Ed25519": AlgorithmProfile("Ed25519", "ecc", "digital_signature", True, 24, "Edwards-curve signatures; quantum-vulnerable"),
    "Ed448": AlgorithmProfile("Ed448", "ecc", "digital_signature", True, 22, "Edwards-curve signatures; quantum-vulnerable"),
    "ECC": AlgorithmProfile("ECC", "ecc", "public_key", True, 26, "Generic elliptic-curve cryptography"),
    "AES": AlgorithmProfile("AES", "symmetric", "encryption", False, 8, "Grover reduces effective strength; 256-bit preferred"),
    "3DES": AlgorithmProfile("3DES", "symmetric", "encryption", False, 22, "Deprecated symmetric cipher"),
    "DES": AlgorithmProfile("DES", "symmetric", "encryption", False, 36, "Broken classical symmetric cipher"),
    "ChaCha20": AlgorithmProfile("ChaCha20", "symmetric", "encryption", False, 8, "Modern stream cipher"),
    "ChaCha20-Poly1305": AlgorithmProfile("ChaCha20-Poly1305", "symmetric", "aead", False, 6, "Modern AEAD"),
    "Blowfish": AlgorithmProfile("Blowfish", "symmetric", "encryption", False, 20, "Legacy 64-bit block cipher"),
    "SHA-1": AlgorithmProfile("SHA-1", "hash", "hashing", False, 28, "Collision-broken hash; not a public-key primitive"),
    "SHA-224": AlgorithmProfile("SHA-224", "hash", "hashing", False, 12, "SHA-2 truncated variant"),
    "SHA-256": AlgorithmProfile("SHA-256", "hash", "hashing", False, 6, "Standard SHA-2"),
    "SHA-384": AlgorithmProfile("SHA-384", "hash", "hashing", False, 4, "SHA-2"),
    "SHA-512": AlgorithmProfile("SHA-512", "hash", "hashing", False, 4, "SHA-2"),
    "MD5": AlgorithmProfile("MD5", "hash", "hashing", False, 34, "Cryptographically broken hash"),
    "PBKDF2": AlgorithmProfile("PBKDF2", "kdf", "password_hashing", False, 10, "KDF; quality depends on iteration count"),
    "bcrypt": AlgorithmProfile("bcrypt", "kdf", "password_hashing", False, 8, "Password hashing"),
    "scrypt": AlgorithmProfile("scrypt", "kdf", "password_hashing", False, 6, "Memory-hard KDF"),
    "Argon2": AlgorithmProfile("Argon2", "kdf", "password_hashing", False, 4, "Modern password hashing"),
    "HMAC": AlgorithmProfile("HMAC", "mac", "mac", False, 8, "Keyed hash MAC"),
    "TLS": AlgorithmProfile("TLS", "protocol", "protocol", False, 10, "Protocol; inspect version and ciphers"),
    "SSL": AlgorithmProfile("SSL", "protocol", "protocol", False, 32, "Legacy SSL must not be used"),
    "SSH": AlgorithmProfile("SSH", "protocol", "protocol", False, 10, "Protocol; inspect host keys and KEX"),
    "IPsec": AlgorithmProfile("IPsec", "protocol", "protocol", False, 10, "Protocol; inspect IKE algorithms"),
    "ML-KEM": AlgorithmProfile("ML-KEM", "pqc", "key_establishment", False, 2, "NIST PQC KEM"),
    "ML-DSA": AlgorithmProfile("ML-DSA", "pqc", "digital_signature", False, 2, "NIST PQC signatures"),
    "SLH-DSA": AlgorithmProfile("SLH-DSA", "pqc", "digital_signature", False, 2, "Stateless hash-based signatures"),
}


LIBRARY_NAMES = {
    "openssl": "OpenSSL",
    "boringssl": "BoringSSL",
    "libressl": "LibreSSL",
    "libsodium": "libsodium",
    "pycryptodome": "PyCryptodome",
    "cryptography": "cryptography",
    "bouncy castle": "Bouncy Castle",
    "bouncycastle": "Bouncy Castle",
    "javax.crypto": "Java JCA/JCE",
    "java.security": "Java JCA/JCE",
    "crypto/tls": "Go crypto",
    "crypto/rsa": "Go crypto",
    "node:crypto": "Node crypto",
    "require(\"crypto\")": "Node crypto",
    "require('crypto')": "Node crypto",
}


def get_profile(algorithm: str) -> AlgorithmProfile:
    return PROFILES.get(algorithm, AlgorithmProfile(algorithm, "unknown", "unknown", False, 12, "Unknown algorithm"))
