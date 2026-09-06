"""Dependency scanner with graceful fallbacks for Syft/Trivy."""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from pathlib import Path

from scanner.common.base import BaseScanner
from scanner.common.catalog import LIBRARY_NAMES
from scanner.common.types import SKIP_DIRS, Detection

CRYPTO_PACKAGES = {
    "cryptography": "cryptography",
    "pycryptodome": "PyCryptodome",
    "pycrypto": "PyCrypto",
    "pyopenssl": "OpenSSL",
    "bcrypt": "bcrypt",
    "argon2-cffi": "Argon2",
    "hashlib": "hashlib",
    "libsodium": "libsodium",
    "openssl": "OpenSSL",
    "bouncycastle": "Bouncy Castle",
    "org.bouncycastle": "Bouncy Castle",
    "golang.org/x/crypto": "Go crypto",
    "crypto": "Node crypto",
}


def _run_optional(cmd: list[str], timeout: int = 20) -> str:
    executable = shutil.which(cmd[0])
    if not executable:
        return ""
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return ""
    return result.stdout


class DependencyScanner(BaseScanner):
    name = "dependencies"

    def scan(self, root: Path) -> list[Detection]:
        detections: list[Detection] = []
        detections.extend(self._requirements(root))
        detections.extend(self._package_json(root))
        detections.extend(self._go_mod(root))
        detections.extend(self._pom(root))
        syft = _run_optional(["syft", str(root), "-o", "json"])
        if syft:
            detections.extend(self._from_syft(syft, root))
        return detections

    def _hit(self, library: str, file: str, evidence: str, version: str = "") -> Detection:
        return Detection(
            algorithm="Library",
            file=file,
            line=1,
            evidence=evidence[:240],
            language="config",
            library=library,
            extra={"library_version": version},
            source_type="dependency",
        )

    def _requirements(self, root: Path) -> list[Detection]:
        out: list[Detection] = []
        for path in root.rglob("requirements*.txt"):
            if any(p in SKIP_DIRS for p in path.parts):
                continue
            for idx, line in enumerate(path.read_text(errors="ignore").splitlines(), start=1):
                lower = line.lower()
                for pkg, lib in CRYPTO_PACKAGES.items():
                    if pkg in lower:
                        version = ""
                        if "==" in line:
                            version = line.split("==", 1)[-1].strip()
                        det = self._hit(lib, str(path.relative_to(root)).replace("\\", "/"), line, version)
                        det.line = idx
                        out.append(det)
        return out

    def _package_json(self, root: Path) -> list[Detection]:
        out: list[Detection] = []
        for path in root.rglob("package.json"):
            if any(p in SKIP_DIRS for p in path.parts):
                continue
            try:
                data = json.loads(path.read_text(errors="ignore") or "{}")
            except json.JSONDecodeError:
                continue
            deps = {**data.get("dependencies", {}), **data.get("devDependencies", {})}
            for name, version in deps.items():
                if name.lower() in CRYPTO_PACKAGES or "crypto" in name.lower() or "forge" in name.lower():
                    out.append(
                        self._hit(
                            LIBRARY_NAMES.get(name.lower(), name),
                            str(path.relative_to(root)).replace("\\", "/"),
                            f"{name}@{version}",
                            str(version),
                        )
                    )
        return out

    def _go_mod(self, root: Path) -> list[Detection]:
        out: list[Detection] = []
        for path in root.rglob("go.mod"):
            if any(p in SKIP_DIRS for p in path.parts):
                continue
            text = path.read_text(errors="ignore")
            if "golang.org/x/crypto" in text or "crypto/" in text:
                out.append(self._hit("Go crypto", str(path.relative_to(root)).replace("\\", "/"), "go.mod crypto dependency"))
        return out

    def _pom(self, root: Path) -> list[Detection]:
        out: list[Detection] = []
        for path in root.rglob("pom.xml"):
            if any(p in SKIP_DIRS for p in path.parts):
                continue
            text = path.read_text(errors="ignore")
            if "bouncycastle" in text.lower() or "bcprov" in text.lower():
                out.append(self._hit("Bouncy Castle", str(path.relative_to(root)).replace("\\", "/"), "pom.xml bouncycastle"))
        return out

    def _from_syft(self, stdout: str, root: Path) -> list[Detection]:
        try:
            payload = json.loads(stdout)
        except json.JSONDecodeError:
            return []
        out: list[Detection] = []
        for artifact in payload.get("artifacts", []):
            name = str(artifact.get("name", "")).lower()
            if any(pkg in name for pkg in CRYPTO_PACKAGES):
                out.append(
                    self._hit(
                        CRYPTO_PACKAGES.get(name, name),
                        "syft",
                        f"syft:{artifact.get('name')}@{artifact.get('version')}",
                        str(artifact.get("version", "")),
                    )
                )
        return out
