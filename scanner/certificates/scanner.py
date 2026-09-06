"""Certificate scanner using the cryptography library; OpenSSL CLI is optional."""

from __future__ import annotations

import hashlib
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa
from cryptography.x509.oid import ExtensionOID, NameOID

from scanner.common.base import BaseScanner
from scanner.common.types import SKIP_DIRS, Detection

CERT_SUFFIXES = {".pem", ".crt", ".cer", ".der"}


class ParsedCertificate:
    def __init__(self, **kwargs) -> None:  # noqa: ANN003
        self.__dict__.update(kwargs)


def _name_to_str(name: x509.Name) -> str:
    parts = []
    for attr in name:
        key = attr.oid._name if attr.oid._name else attr.oid.dotted_string  # noqa: SLF001
        parts.append(f"{key}={attr.value}")
    return ", ".join(parts)


def parse_certificate_bytes(data: bytes, file_path: str = "") -> ParsedCertificate | None:
    try:
        cert = x509.load_pem_x509_certificate(data)
    except ValueError:
        try:
            cert = x509.load_der_x509_certificate(data)
        except ValueError:
            return None

    public_key = cert.public_key()
    key_size = None
    curve = ""
    algo = public_key.__class__.__name__
    if isinstance(public_key, rsa.RSAPublicKey):
        algo = "RSA"
        key_size = public_key.key_size
    elif isinstance(public_key, dsa.DSAPublicKey):
        algo = "DSA"
        key_size = public_key.key_size
    elif isinstance(public_key, ec.EllipticCurvePublicKey):
        algo = "ECDSA"
        key_size = public_key.curve.key_size
        curve = public_key.curve.name
    elif isinstance(public_key, ed25519.Ed25519PublicKey):
        algo = "Ed25519"
        key_size = 256
        curve = "Ed25519"
    elif isinstance(public_key, ed448.Ed448PublicKey):
        algo = "Ed448"
        key_size = 448
        curve = "Ed448"

    san = ""
    try:
        ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        san = ", ".join(ext.value.get_values_for_type(x509.DNSName))
    except x509.ExtensionNotFound:
        san = ""

    not_after = cert.not_valid_after_utc
    not_before = cert.not_valid_before_utc
    fingerprint = hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest()
    sig_algo = cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else cert.signature_algorithm_oid._name  # noqa: SLF001
    try:
        common_name = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    except IndexError:
        common_name = ""

    now = datetime.now(timezone.utc)
    return ParsedCertificate(
        file_path=file_path,
        subject=_name_to_str(cert.subject),
        issuer=_name_to_str(cert.issuer),
        serial_number=format(cert.serial_number, "x"),
        not_before=not_before.replace(tzinfo=None),
        not_after=not_after.replace(tzinfo=None),
        signature_algorithm=sig_algo,
        public_key_algorithm=algo,
        key_size=key_size,
        curve=curve,
        san=san,
        expired=now > not_after,
        fingerprint_sha256=fingerprint,
        common_name=common_name,
    )


def openssl_available() -> bool:
    return shutil.which("openssl") is not None


def openssl_text(path: Path) -> str:
    if not openssl_available():
        return ""
    try:
        result = subprocess.run(
            ["openssl", "x509", "-in", str(path), "-noout", "-text"],
            capture_output=True,
            text=True,
            timeout=8,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return ""
    return result.stdout[:4000]


class CertificateScanner(BaseScanner):
    name = "certificates"

    def scan(self, root: Path) -> tuple[list[Detection], list[ParsedCertificate]]:
        detections: list[Detection] = []
        certs: list[ParsedCertificate] = []
        for path in root.rglob("*"):
            if not path.is_file() or any(part in SKIP_DIRS for part in path.parts):
                continue
            if path.suffix.lower() not in CERT_SUFFIXES:
                continue
            try:
                data = path.read_bytes()
            except OSError:
                continue
            parsed = parse_certificate_bytes(data, str(path.relative_to(root)).replace("\\", "/"))
            if not parsed:
                continue
            certs.append(parsed)
            detections.append(
                Detection(
                    algorithm=parsed.public_key_algorithm,
                    file=parsed.file_path,
                    line=1,
                    evidence=(
                        f"cert {parsed.public_key_algorithm}-{parsed.key_size or parsed.curve} "
                        f"sig={parsed.signature_algorithm}"
                    ),
                    language="certificate",
                    key_size=parsed.key_size,
                    curve=parsed.curve,
                    protocol="TLS",
                    source_type="certificate",
                )
            )
            if "sha1" in (parsed.signature_algorithm or "").lower():
                detections.append(
                    Detection(
                        algorithm="SHA-1",
                        file=parsed.file_path,
                        line=1,
                        evidence=f"certificate signature algorithm {parsed.signature_algorithm}",
                        language="certificate",
                        protocol="TLS",
                        source_type="certificate",
                    )
                )
        return detections, certs
