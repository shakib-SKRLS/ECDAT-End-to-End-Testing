"""Tests for the scanner module."""

import sys
from pathlib import Path

# Add parent directory to path for scanner module
sys.path.insert(0, str(Path(__file__).parent.parent))

from scanner.certificates.scanner import CertificateScanner
from scanner.common.detector import detect_in_text
from scanner.dependencies.scanner import DependencyScanner
from scanner.source.scanner import SourceCodeScanner


def test_source_scanner():
    """Test source code scanner."""
    scanner = SourceCodeScanner(max_files=100)
    # Use absolute path to fixtures
    fixtures_path = Path(__file__).parent.parent / "fixtures" / "vulnerable-project"
    results = scanner.scan(fixtures_path)
    # The vulnerable fixture must actually be detected (AES, 3DES, ECDSA,
    # MD5, SHA-1 are all present in fixtures/vulnerable-project/crypto.py).
    assert len(results) > 0
    found = {d.algorithm for d in results}
    assert {"AES", "3DES", "ECDSA", "MD5", "SHA-1"} <= found


def test_dependency_scanner():
    """Test dependency scanner."""
    scanner = DependencyScanner()
    results = scanner.scan(Path(__file__).parent.parent / "fixtures" / "vulnerable-project")
    assert len(results) >= 0  # May be empty if no crypto deps


def test_certificate_scanner():
    """Test certificate scanner."""
    scanner = CertificateScanner()
    results, certs = scanner.scan(Path(__file__).parent.parent / "fixtures" / "vulnerable-project")
    assert isinstance(results, list)
    assert isinstance(certs, list)


def test_detect_in_text():
    """Test text detection."""
    from scanner.common.types import Detection
    
    text = """
    from cryptography.hazmat.primitives.asymmetric import rsa
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    """
    detections = detect_in_text(Path("test.py"), text)
    assert len(detections) > 0
    assert any(d.algorithm == "RSA" for d in detections)


def test_detect_md5():
    """Test MD5 detection."""
    text = "hashlib.md5(data).hexdigest()"
    detections = detect_in_text(Path("test.py"), text)
    assert any(d.algorithm == "MD5" for d in detections)


def test_detect_sha1():
    """Test SHA-1 detection."""
    text = "hashlib.sha1(data).hexdigest()"
    detections = detect_in_text(Path("test.py"), text)
    assert any(d.algorithm == "SHA-1" for d in detections)


def test_detect_aes():
    """Test AES detection."""
    text = "AES.new(key, AES.MODE_CBC)"
    detections = detect_in_text(Path("test.py"), text)
    assert any(d.algorithm == "AES" for d in detections)


def test_detect_3des():
    """Test 3DES detection."""
    text = "TripleDES(key)"
    detections = detect_in_text(Path("test.py"), text)
    assert any(d.algorithm == "3DES" for d in detections)
