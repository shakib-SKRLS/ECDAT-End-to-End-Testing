"""CBOM (Cryptographic Bill of Materials) generator."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from scanner.common.catalog import get_profile
from scanner.common.types import Detection

from app.pqc.recommendations import recommend
from app.risk.engine import RiskInputs, classify_asset, score_asset


class CBOMEntry:
    def __init__(
        self,
        project_id: str,
        scan_id: str,
        detection: Detection,
        data_lifetime_years: float,
        migration_time_years: float,
        quantum_threat_horizon_years: float,
        business_criticality: int,
        exposure: str,
    ) -> None:
        self.project_id = project_id
        self.scan_id = scan_id
        self.detection = detection
        self.profile = get_profile(detection.algorithm)
        
        # Risk calculation
        risk_inputs = RiskInputs(
            algorithm=detection.algorithm,
            key_size=detection.key_size,
            primitive_type=self.profile.primitive_type,
            data_lifetime_years=data_lifetime_years,
            migration_time_years=migration_time_years,
            quantum_threat_horizon_years=quantum_threat_horizon_years,
            business_criticality=business_criticality,
            exposure=exposure,
        )
        self.risk_score, self.severity = score_asset(risk_inputs)
        self.classification = classify_asset(
            detection.algorithm,
            self.profile.quantum_vulnerable,
            self.risk_score,
        )
        
        # PQC recommendations
        pqc_advice = recommend(detection.algorithm, self.profile.primitive_type, detection.key_size)
        self.recommendation = pqc_advice.recommendation
        self.pqc_candidate = pqc_advice.candidate
        self.migration_priority = self._migration_priority()
        
    def _migration_priority(self) -> str:
        if self.severity == "CRITICAL":
            return "CRITICAL"
        if self.severity == "HIGH" or self.profile.quantum_vulnerable:
            return "HIGH"
        if self.severity == "MEDIUM":
            return "MEDIUM"
        return "LOW"
    
    def to_dict(self) -> dict[str, Any]:
        return {
            "algorithm": self.detection.algorithm,
            "algorithm_family": self.profile.family,
            "primitive_type": self.profile.primitive_type,
            "key_size": self.detection.key_size,
            "curve": self.detection.curve,
            "mode": self.detection.mode,
            "protocol": self.detection.protocol,
            "library": self.detection.library,
            "library_version": self.detection.extra.get("library_version", ""),
            "file_path": self.detection.file,
            "line_number": self.detection.line,
            "language": self.detection.language,
            "source_type": self.detection.source_type,
            "evidence": self.detection.evidence,
            "classical_security_status": self._classical_status(),
            "quantum_security_status": "vulnerable" if self.profile.quantum_vulnerable else "resilient",
            "risk_score": self.risk_score,
            "severity": self.severity,
            "recommendation": self.recommendation,
            "migration_priority": self.migration_priority,
            "pqc_candidate": self.pqc_candidate,
            "classification": self.classification,
        }
    
    def _classical_status(self) -> str:
        if self.detection.algorithm in {"MD5", "SHA-1", "DES", "SSL"}:
            return "broken"
        if self.detection.algorithm in {"3DES", "TLS 1.0", "TLS 1.1"}:
            return "deprecated"
        if self.detection.algorithm == "RSA" and self.detection.key_size and self.detection.key_size < 2048:
            return "weak"
        return "acceptable"


class CBOMGenerator:
    def __init__(self) -> None:
        pass
    
    def generate(
        self,
        project_id: str,
        scan_id: str,
        detections: list[Detection],
        data_lifetime_years: float = 5.0,
        migration_time_years: float = 3.0,
        quantum_threat_horizon_years: float = 10.0,
        business_criticality: int = 3,
        exposure: str = "internal",
    ) -> list[CBOMEntry]:
        entries: list[CBOMEntry] = []
        for detection in detections:
            entry = CBOMEntry(
                project_id=project_id,
                scan_id=scan_id,
                detection=detection,
                data_lifetime_years=data_lifetime_years,
                migration_time_years=migration_time_years,
                quantum_threat_horizon_years=quantum_threat_horizon_years,
                business_criticality=business_criticality,
                exposure=exposure,
            )
            entries.append(entry)
        return entries
    
    def to_json(self, entries: list[CBOMEntry]) -> dict[str, Any]:
        return {
            "bom_format": "CBOM",
            "spec_version": "1.0",
            "metadata": {
                "timestamp": datetime.utcnow().isoformat(),
                "tools": [{"name": "ECDAT Scanner", "version": "0.1.0"}],
            },
            "components": [entry.to_dict() for entry in entries],
        }
    
    def to_csv(self, entries: list[CBOMEntry]) -> str:
        import io
        import csv
        
        output = io.StringIO()
        fieldnames = [
            "algorithm",
            "algorithm_family",
            "primitive_type",
            "key_size",
            "curve",
            "mode",
            "protocol",
            "library",
            "file_path",
            "line_number",
            "language",
            "evidence",
            "classical_security_status",
            "quantum_security_status",
            "risk_score",
            "severity",
            "recommendation",
            "migration_priority",
            "pqc_candidate",
            "classification",
        ]
        writer = csv.DictWriter(output, fieldnames=fieldnames)
        writer.writeheader()
        for entry in entries:
            writer.writerow(entry.to_dict())
        return output.getvalue()
