"""Deterministic PQC / migration recommendations by primitive type.

Recommendations are investigation starting points, not drop-in replacements.
"""

from __future__ import annotations

from dataclasses import dataclass

from scanner.common.catalog import get_profile


@dataclass
class PqcAdvice:
    candidate: str
    recommendation: str
    migration_notes: str
    why_it_matters: str
    remediation: str


def recommend(algorithm: str, primitive_type: str = "", key_size: int | None = None) -> PqcAdvice:
    profile = get_profile(algorithm)
    primitive = primitive_type or profile.primitive_type

    if algorithm == "PrivateKeyMaterial":
        return PqcAdvice(
            candidate="n/a",
            recommendation="Remove embedded private keys from source and rotate immediately.",
            migration_notes="Secret exposure is a classical incident. Do not store key material in git.",
            why_it_matters="Private key material in repositories can be copied independently of quantum risk.",
            remediation="Rotate the key, purge history if required, and load keys from a HSM/secret manager.",
        )

    if primitive in {"key_establishment", "public_key"} and algorithm in {"RSA", "DH", "ECDH", "ECC"}:
        return PqcAdvice(
            candidate="ML-KEM (investigate hybrid ML-KEM + classical KEM)",
            recommendation="Investigate ML-KEM for key establishment, preferably in a hybrid mode during transition.",
            migration_notes=(
                "RSA, DH, and ECDH are not interchangeable with a single PQC KEM without protocol work. "
                "Hybrid TLS/IKE designs preserve classical security if PQC is later weakened."
            ),
            why_it_matters="Shor's algorithm would break these key-establishment primitives.",
            remediation="Inventory protocol usage, trial hybrid KEMs in non-production, then migrate endpoints.",
        )

    if primitive == "digital_signature" or algorithm in {"ECDSA", "DSA", "Ed25519", "Ed448"} or (
        algorithm == "RSA" and primitive == "digital_signature"
    ):
        return PqcAdvice(
            candidate="ML-DSA; SLH-DSA as hash-based option",
            recommendation="Investigate ML-DSA for general signatures; consider SLH-DSA where hash-based conservative signatures are required.",
            migration_notes=(
                "Signature algorithms are not drop-in replacements: certificate profiles, firmware size, "
                "and handshake latency change. RSA signatures and ECDSA need separate migration tracks from RSA encryption."
            ),
            why_it_matters="Forged signatures would undermine authenticity after a cryptographically relevant quantum computer exists.",
            remediation="Pilot PQC certificates and code-signing in a lab; update PKI policy before production cutover.",
        )

    if algorithm == "RSA":
        return PqcAdvice(
            candidate="ML-KEM (encryption/KEM) and/or ML-DSA (signatures)",
            recommendation="Split RSA uses: encryption/key transport toward ML-KEM; signatures toward ML-DSA.",
            migration_notes="Do not treat ML-KEM and ML-DSA as interchangeable. Identify each RSA call site's primitive.",
            why_it_matters="RSA is quantum-vulnerable for both encryption and signatures.",
            remediation="Classify each RSA usage, then migrate by primitive rather than by library name.",
        )

    if primitive in {"encryption", "aead"} or algorithm in {"AES", "ChaCha20", "ChaCha20-Poly1305"}:
        size_note = ""
        if algorithm == "AES" and key_size and key_size < 256:
            size_note = " Prefer AES-256 to retain margin against Grover-style search."
        return PqcAdvice(
            candidate="AES-256 / ChaCha20-Poly1305 (not a PQC public-key primitive)",
            recommendation="Symmetric ciphers are not replaced by ML-KEM. Keep modern AEAD; increase key length where appropriate.",
            migration_notes=(
                "Quantum impact on symmetric cryptography is different from public-key cryptography. "
                "Grover's algorithm motivates longer keys; it does not make AES equivalent to RSA risk."
            )
            + size_note,
            why_it_matters="Confidentiality still depends on mode, nonce handling, and key management.",
            remediation="Ban ECB, require GCM/ChaCha20-Poly1305, and enforce 256-bit keys for long-lived data.",
        )

    if primitive == "hashing" or algorithm in {"MD5", "SHA-1", "SHA-256", "SHA-384", "SHA-512", "SHA-224"}:
        if algorithm in {"MD5", "SHA-1"}:
            return PqcAdvice(
                candidate="SHA-256 or SHA-384 (classical hash upgrade)",
                recommendation="Replace MD5/SHA-1 immediately for integrity and certificates; this is a classical break, not only a PQC issue.",
                migration_notes="Hash function upgrades are not PQC KEMs. Do not map MD5 to ML-KEM.",
                why_it_matters="MD5 and SHA-1 are collision-broken today.",
                remediation="Switch checksums, HMAC keys, and certificate signatures off SHA-1/MD5.",
            )
        return PqcAdvice(
            candidate="SHA-384 / SHA-512 (internal hash strength)",
            recommendation="SHA-2 remains appropriate; quantum impact is a security-level reduction, not a Shor break.",
            migration_notes="Hashing is not migrated to ML-DSA/ML-KEM unless it is used inside signatures/certificates.",
            why_it_matters="Hashes used inside signatures inherit the outer public-key quantum risk.",
            remediation="Keep SHA-2/SHA-3; review HMAC key length and protocol binding.",
        )

    if primitive == "password_hashing":
        return PqcAdvice(
            candidate="Argon2id",
            recommendation="Use a modern password KDF (Argon2id). This is not a PQC public-key migration.",
            migration_notes="PBKDF2/bcrypt/scrypt concerns are classical password-guessing, distinct from Shor-based RSA/ECC breaks.",
            why_it_matters="Password hashes protect authentication secrets at rest.",
            remediation="Adopt Argon2id with memory-hard parameters; never store raw MD5/SHA-1 passwords.",
        )

    if primitive == "protocol" or algorithm in {"TLS", "SSL", "SSH", "IPsec"}:
        return PqcAdvice(
            candidate="Hybrid TLS 1.3 / PQ-aware IKE and SSH",
            recommendation="Disable SSL/legacy TLS, then plan hybrid post-quantum key exchange in TLS/SSH/IPsec.",
            migration_notes="Protocol upgrades require peer interoperability. Algorithm substitution inside old SSL is not sufficient.",
            why_it_matters="Handshake algorithms determine whether session keys are quantum-vulnerable.",
            remediation="Set minimum TLS 1.2+ (prefer 1.3), disable SSLv3, and trial hybrid KEX with vendors.",
        )

    return PqcAdvice(
        candidate="review",
        recommendation="Manually classify this primitive before selecting a PQC candidate.",
        migration_notes="Unknown detections should not be auto-mapped onto a NIST PQC algorithm.",
        why_it_matters="Incorrect substitution can break interoperability or weaken security.",
        remediation="Confirm library, primitive, and protocol, then re-run analysis.",
    )
