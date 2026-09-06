"""Container/image scanner adapter. Trivy is optional; Dockerfiles are always parsed."""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

from scanner.common.base import BaseScanner
from scanner.common.detector import detect_in_text
from scanner.common.types import SKIP_DIRS, Detection


class ContainerScanner(BaseScanner):
    name = "containers"

    def scan(self, root: Path) -> list[Detection]:
        detections: list[Detection] = []
        for path in root.rglob("*"):
            if not path.is_file() or any(p in SKIP_DIRS for p in path.parts):
                continue
            name = path.name.lower()
            if name == "dockerfile" or name.startswith("dockerfile") or name.endswith(".dockerfile"):
                text = path.read_text(encoding="utf-8", errors="ignore")
                rel = str(path.relative_to(root)).replace("\\", "/")
                found = detect_in_text(path, text)
                for item in found:
                    item.file = rel
                    item.source_type = "container"
                    item.language = "dockerfile"
                detections.extend(found)
                if "libssl" in text.lower() or "openssl" in text.lower():
                    detections.append(
                        Detection(
                            algorithm="TLS",
                            file=rel,
                            line=1,
                            evidence="Dockerfile references OpenSSL/libssl",
                            language="dockerfile",
                            library="OpenSSL",
                            protocol="TLS",
                            source_type="container",
                        )
                    )
        detections.extend(self._trivy_if_available(root))
        return detections

    def _trivy_if_available(self, root: Path) -> list[Detection]:
        if not shutil.which("trivy"):
            return []
        try:
            result = subprocess.run(
                ["trivy", "fs", "--format", "json", "--quiet", str(root)],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            return []
        try:
            payload = json.loads(result.stdout or "{}")
        except json.JSONDecodeError:
            return []
        out: list[Detection] = []
        for report in payload.get("Results", []) if isinstance(payload, dict) else []:
            for vuln in report.get("Vulnerabilities") or []:
                title = str(vuln.get("Title", "")).lower()
                if any(token in title for token in ("ssl", "tls", "rsa", "openssl", "crypto")):
                    out.append(
                        Detection(
                            algorithm="TLS",
                            file=str(report.get("Target", "trivy")),
                            line=1,
                            evidence=str(vuln.get("VulnerabilityID", "trivy"))[:240],
                            language="container",
                            library=str(vuln.get("PkgName", "")),
                            source_type="container",
                        )
                    )
        return out


class CloudScanner(BaseScanner):
    """Adapter stub for future cloud KMS/certificate inventory."""

    name = "cloud"

    def scan(self, root: Path) -> list[Detection]:
        return []
