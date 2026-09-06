"""Scanner CLI entry point."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from scanner.certificates.scanner import CertificateScanner
from scanner.common.catalog import get_profile
from scanner.common.detector import detect_in_text
from scanner.common.types import Detection
from scanner.containers.scanner import ContainerScanner
from scanner.dependencies.scanner import DependencyScanner
from scanner.source.scanner import SourceCodeScanner


def main() -> None:
    parser = argparse.ArgumentParser(description="ECDAT Cryptographic Scanner")
    parser.add_argument("path", type=Path, help="Path to scan")
    parser.add_argument("--output", "-o", type=Path, help="Output file (JSON)")
    parser.add_argument("--format", "-f", choices=["json", "text"], default="text", help="Output format")
    parser.add_argument("--max-files", type=int, default=20000, help="Max files to scan")
    parser.add_argument("--workers", type=int, default=8, help="Scan workers")
    args = parser.parse_args()

    root = args.path.resolve()
    if not root.exists():
        print(f"Error: Path {root} does not exist", file=sys.stderr)
        sys.exit(1)

    print(f"Scanning {root}...")

    all_detections: list[Detection] = []
    
    # Source code scanner
    print("  - Source code...")
    source_scanner = SourceCodeScanner(max_files=args.max_files, workers=args.workers)
    all_detections.extend(source_scanner.scan(root))
    
    # Dependency scanner
    print("  - Dependencies...")
    dep_scanner = DependencyScanner()
    all_detections.extend(dep_scanner.scan(root))
    
    # Certificate scanner
    print("  - Certificates...")
    cert_scanner = CertificateScanner()
    cert_detections, certs = cert_scanner.scan(root)
    all_detections.extend(cert_detections)
    
    # Container scanner
    print("  - Containers...")
    container_scanner = ContainerScanner()
    all_detections.extend(container_scanner.scan(root))

    print(f"Found {len(all_detections)} detections")

    # Convert to CBOM-like format
    cbom = []
    for d in all_detections:
        profile = get_profile(d.algorithm)
        cbom.append({
            "algorithm": d.algorithm,
            "algorithm_family": profile.family,
            "primitive_type": profile.primitive_type,
            "key_size": d.key_size,
            "curve": d.curve,
            "mode": d.mode,
            "protocol": d.protocol,
            "library": d.library,
            "file_path": d.file,
            "line": d.line,
            "language": d.language,
            "source_type": d.source_type,
            "evidence": d.evidence,
            "quantum_vulnerable": profile.quantum_vulnerable,
        })

    if args.format == "json":
        output = json.dumps({
            "scan_path": str(root),
            "total_detections": len(all_detections),
            "detections": cbom,
            "certificates": [
                {
                    "file_path": c.file_path,
                    "subject": c.subject,
                    "issuer": c.issuer,
                    "public_key_algorithm": c.public_key_algorithm,
                    "key_size": c.key_size,
                    "curve": c.curve,
                    "expired": c.expired,
                }
                for c in certs
            ],
        }, indent=2)
    else:
        output = f"Scan Results for {root}\n"
        output += f"Total detections: {len(all_detections)}\n\n"
        for d in all_detections:
            output += f"{d.algorithm} in {d.file}:{d.line}\n"
            output += f"  Evidence: {d.evidence[:100]}\n\n"

    if args.output:
        args.output.write_text(output)
        print(f"Output written to {args.output}")
    else:
        print(output)


if __name__ == "__main__":
    main()
