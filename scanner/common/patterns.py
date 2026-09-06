"""Regex/pattern catalog for multi-language cryptographic discovery."""

from __future__ import annotations

from dataclasses import dataclass
import re


@dataclass(frozen=True)
class DetectionPattern:
    algorithm: str
    regex: str
    languages: tuple[str, ...]
    library: str = ""
    primitive_hint: str = ""
    protocol: str = ""
    flags: int = re.IGNORECASE


PATTERNS: list[DetectionPattern] = [
    # Python
    DetectionPattern("RSA", r"RSA\.generate\s*\(\s*(?P<key_size>\d+)", ("python",), "PyCryptodome"),
    DetectionPattern("RSA", r"rsa\.generate_private_key\s*\([^)]*key_size\s*=\s*(?P<key_size>\d+)", ("python",), "cryptography"),
    DetectionPattern("RSA", r"PKCS1_OAEP|RSAPublicKey|RSAPrivateKey", ("python",), "cryptography"),
    DetectionPattern("ECDSA", r"ec\.generate_private_key\s*\(\s*ec\.(?P<curve>SECP\w+)", ("python",), "cryptography"),
    DetectionPattern("ECDSA", r"ecdsa\.(SigningKey|VerifyingKey)|NIST256p|NIST384p", ("python",), "ecdsa"),
    DetectionPattern("ECDH", r"ECDH\(|exchange\s*=\s*ec\.ECDH", ("python",), "cryptography"),
    DetectionPattern("DH", r"dh\.generate_parameters|DHParameterNumbers", ("python",), "cryptography"),
    DetectionPattern("Ed25519", r"Ed25519(PrivateKey|PublicKey)|ed25519", ("python",), "cryptography"),
    DetectionPattern("Ed448", r"Ed448(PrivateKey|PublicKey)", ("python",), "cryptography"),
    DetectionPattern("AES", r"AES\.new\s*\(|algorithms\.AES\s*\(|Cipher\.AES", ("python",)),
    DetectionPattern("AES", r"AES-(?P<key_size>128|192|256)|aes-(?P<key_size2>128|192|256)", ("python", "javascript", "config")),
    DetectionPattern("3DES", r"TripleDES|DES3|3DES|algorithms\.TripleDES", ("python", "java", "javascript")),
    DetectionPattern("DES", r"(?<![A-Za-z0-9_])DES\.new|algorithms\.DES(?!3)|Cipher\.getInstance\(\s*[\"']DES", ("python", "java")),
    DetectionPattern("ChaCha20-Poly1305", r"ChaCha20Poly1305|chacha20-poly1305", ("python", "javascript", "go")),
    DetectionPattern("ChaCha20", r"ChaCha20(?!Poly1305)|algorithms\.ChaCha20", ("python",)),
    DetectionPattern("Blowfish", r"Blowfish", ("python", "java", "c")),
    DetectionPattern("MD5", r"hashlib\.md5|md5\s*\(|MessageDigest\.getInstance\(\s*[\"']MD5|crypto\.createHash\(\s*[\"']md5", ("python", "java", "javascript", "go", "c")),
    DetectionPattern("SHA-1", r"hashlib\.sha1|sha1\s*\(|[\"']SHA-1[\"']|SHA1withRSA|createHash\(\s*[\"']sha1", ("python", "java", "javascript", "go", "c", "config")),
    DetectionPattern("SHA-224", r"sha224|SHA-224|SHA224", ("python", "java", "javascript")),
    DetectionPattern("SHA-256", r"hashlib\.sha256|sha256\s*\(|SHA-256|SHA256withRSA|createHash\(\s*[\"']sha256", ("python", "java", "javascript", "go", "c", "config")),
    DetectionPattern("SHA-384", r"sha384|SHA-384|SHA384", ("python", "java", "javascript", "config")),
    DetectionPattern("SHA-512", r"sha512|SHA-512|SHA512", ("python", "java", "javascript", "config")),
    DetectionPattern("PBKDF2", r"PBKDF2|pbkdf2_hmac|pbkdf2Sync", ("python", "javascript", "java")),
    DetectionPattern("bcrypt", r"bcrypt", ("python", "javascript", "java", "go")),
    DetectionPattern("scrypt", r"scrypt", ("python", "javascript", "go")),
    DetectionPattern("Argon2", r"argon2", ("python", "javascript", "go")),
    DetectionPattern("HMAC", r"hmac\.new|createHmac|Mac\.getInstance\(\s*[\"']Hmac", ("python", "javascript", "java")),
    # Java
    DetectionPattern("RSA", r"KeyPairGenerator\.getInstance\(\s*[\"']RSA[\"']|Cipher\.getInstance\(\s*[\"']RSA", ("java",), "Java JCA/JCE"),
    DetectionPattern("RSA", r"RSA/ECB|SHA256withRSA|SHA1withRSA", ("java",), "Java JCA/JCE"),
    DetectionPattern("ECDSA", r"KeyPairGenerator\.getInstance\(\s*[\"']EC[\"']|SHA256withECDSA", ("java",), "Java JCA/JCE"),
    DetectionPattern("AES", r"Cipher\.getInstance\(\s*[\"']AES", ("java",), "Java JCA/JCE"),
    DetectionPattern("DSA", r"KeyPairGenerator\.getInstance\(\s*[\"']DSA[\"']", ("java",), "Java JCA/JCE"),
    DetectionPattern("ECC", r"org\.bouncycastle|BouncyCastleProvider", ("java",), "Bouncy Castle"),
    # JavaScript / TypeScript
    DetectionPattern("RSA", r"generateKeyPair(?:Sync)?\(\s*[\"']rsa[\"']", ("javascript",), "Node crypto"),
    DetectionPattern("ECDSA", r"generateKeyPair(?:Sync)?\(\s*[\"']ec[\"']", ("javascript",), "Node crypto"),
    DetectionPattern("Ed25519", r"generateKeyPair(?:Sync)?\(\s*[\"']ed25519[\"']", ("javascript",), "Node crypto"),
    DetectionPattern("AES", r"createCipheriv\(\s*[\"']aes-(?P<key_size>128|192|256)", ("javascript",), "Node crypto"),
    DetectionPattern("DH", r"createDiffieHellman|diffieHellman", ("javascript",), "Node crypto"),
    DetectionPattern("ECDH", r"createECDH\(", ("javascript",), "Node crypto"),
    # Go
    DetectionPattern("RSA", r"rsa\.GenerateKey|crypto/rsa", ("go",), "Go crypto"),
    DetectionPattern("ECDSA", r"ecdsa\.GenerateKey|crypto/ecdsa", ("go",), "Go crypto"),
    DetectionPattern("ECDH", r"ecdh\.P256|crypto/ecdh", ("go",), "Go crypto"),
    DetectionPattern("Ed25519", r"ed25519\.GenerateKey|crypto/ed25519", ("go",), "Go crypto"),
    DetectionPattern("AES", r"aes\.NewCipher|crypto/aes", ("go",), "Go crypto"),
    DetectionPattern("MD5", r"md5\.Sum|crypto/md5", ("go",), "Go crypto"),
    DetectionPattern("SHA-1", r"sha1\.Sum|crypto/sha1", ("go",), "Go crypto"),
    DetectionPattern("SHA-256", r"sha256\.Sum256|crypto/sha256", ("go",), "Go crypto"),
    DetectionPattern("TLS", r"crypto/tls|tls\.Config", ("go",), "Go crypto", protocol="TLS"),
    # C / C++
    DetectionPattern("RSA", r"RSA_generate_key|EVP_PKEY_RSA|PEM_read_RSA", ("c",), "OpenSSL"),
    DetectionPattern("ECDSA", r"EC_KEY_new|EVP_PKEY_EC|ECDSA_do_sign", ("c",), "OpenSSL"),
    DetectionPattern("ECDH", r"ECDH_compute_key", ("c",), "OpenSSL"),
    DetectionPattern("DH", r"DH_generate_parameters|DH_compute_key", ("c",), "OpenSSL"),
    DetectionPattern("AES", r"EVP_aes_|AES_encrypt|AES_set_encrypt_key", ("c",), "OpenSSL"),
    DetectionPattern("MD5", r"EVP_md5\s*\(|MD5\s*\(", ("c",), "OpenSSL"),
    DetectionPattern("SHA-1", r"EVP_sha1\s*\(|SHA1\s*\(", ("c",), "OpenSSL"),
    DetectionPattern("SHA-256", r"EVP_sha256\s*\(|SHA256\s*\(", ("c",), "OpenSSL"),
    DetectionPattern("3DES", r"EVP_des_ede3|DES_ede3", ("c",), "OpenSSL"),
    DetectionPattern("Ed25519", r"EVP_PKEY_ED25519", ("c",), "OpenSSL"),
    # Protocols / config
    DetectionPattern("TLS", r"tls[_-]?(version|min|max)|ssl_protocols|TLSv1(\.[0-3])?", ("config", "yaml", "json", "xml", "dockerfile"), protocol="TLS"),
    DetectionPattern("SSL", r"SSLv2|SSLv3|ssl_version", ("config", "yaml", "c"), protocol="SSL"),
    DetectionPattern("SSH", r"HostKeyAlgorithms|KexAlgorithms|sshd_config|ssh-rsa", ("config",), protocol="SSH"),
    DetectionPattern("IPsec", r"ikev2|esp-aes|ipsec", ("config",), protocol="IPsec"),
    DetectionPattern("RSA", r"ssh-rsa|rsa-sha2-(256|512)", ("config",), protocol="SSH"),
    # Libraries
    DetectionPattern("AES", r"from Cryptodome|from Crypto\.Cipher", ("python",), "PyCryptodome"),
    DetectionPattern("RSA", r"import openssl|libssl|#include <openssl", ("c", "python", "dockerfile"), "OpenSSL"),
]


COMPILED = [(p, re.compile(p.regex, p.flags)) for p in PATTERNS]

KEY_SIZE_PATTERNS = [
    re.compile(r"key[_-]?size\s*[=:]\s*(\d{3,5})", re.I),
    re.compile(r"modulus\s*[=:]\s*(\d{3,5})", re.I),
    re.compile(r"RSA[_-]?(\d{3,5})"),
    re.compile(r"AES[_-]?(\d{3})", re.I),
]

CURVE_PATTERNS = [
    re.compile(r"(SECP256R1|P-256|prime256v1|NIST256p)", re.I),
    re.compile(r"(SECP384R1|P-384|secp384r1|NIST384p)", re.I),
    re.compile(r"(SECP521R1|P-521|secp521r1)", re.I),
    re.compile(r"(X25519|curve25519)", re.I),
]

MODE_PATTERNS = [
    re.compile(r"\b(GCM|CBC|CTR|ECB|OFB|CFB|ChaCha20-Poly1305)\b", re.I),
]
