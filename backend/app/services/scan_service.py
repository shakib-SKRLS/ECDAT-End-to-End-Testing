"""Scan execution service integrating scanner with database."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any

from sqlalchemy.orm import Session

from app.cbom.generator import CBOMGenerator
from app.models.entities import (
    CryptoAsset,
    Finding,
    Project,
    RiskAssessment,
    Scan,
    MigrationRecommendation,
)
from app.pqc.recommendations import recommend
from app.risk.engine import RiskInputs, classify_asset, score_asset
from app.risk.mosca import assess_mosca
from scanner.certificates.scanner import CertificateScanner
from scanner.common.catalog import get_profile
from scanner.common.types import Detection
from scanner.containers.scanner import ContainerScanner
from scanner.dependencies.scanner import DependencyScanner
from scanner.source.scanner import SourceCodeScanner


class ScanService:
    def __init__(self, db: Session) -> None:
        self.db = db
        self.cbom_generator = CBOMGenerator()
    
    def execute_scan(self, scan_id: str) -> None:
        """Execute a scan and store results in database."""
        scan = self.db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan:
            return
        
        # Update scan status
        scan.status = "running"
        scan.started_at = datetime.utcnow()
        scan.progress = 0
        self.db.commit()
        
        try:
            # Get project
            project = self.db.query(Project).filter(Project.id == scan.project_id).first()
            if not project:
                raise ValueError("Project not found")
            
            # Scan path
            scan_path = Path(scan.source_location)
            if not scan_path.exists():
                raise ValueError(f"Scan path does not exist: {scan_path}")
            
            # Run scanners
            all_detections: list[Detection] = []
            
            # Source code
            source_scanner = SourceCodeScanner()
            all_detections.extend(source_scanner.scan(scan_path))
            scan.progress = 25
            self.db.commit()
            
            # Dependencies
            dep_scanner = DependencyScanner()
            all_detections.extend(dep_scanner.scan(scan_path))
            scan.progress = 50
            self.db.commit()
            
            # Certificates
            cert_scanner = CertificateScanner()
            cert_detections, certs = cert_scanner.scan(scan_path)
            all_detections.extend(cert_detections)
            scan.progress = 75
            self.db.commit()
            
            # Containers
            container_scanner = ContainerScanner()
            all_detections.extend(container_scanner.scan(scan_path))
            scan.progress = 90
            self.db.commit()
            
            # Store certificates
            for cert in certs:
                from app.models.entities import Certificate
                existing = self.db.query(Certificate).filter(
                    Certificate.project_id == project.id,
                    Certificate.fingerprint_sha256 == cert.fingerprint_sha256
                ).first()
                if not existing:
                    db_cert = Certificate(
                        project_id=project.id,
                        scan_id=scan.id,
                        file_path=cert.file_path,
                        subject=cert.subject,
                        issuer=cert.issuer,
                        serial_number=cert.serial_number,
                        not_before=cert.not_before,
                        not_after=cert.not_after,
                        signature_algorithm=cert.signature_algorithm,
                        public_key_algorithm=cert.public_key_algorithm,
                        key_size=cert.key_size,
                        curve=cert.curve,
                        san=cert.san,
                        expired=cert.expired,
                        fingerprint_sha256=cert.fingerprint_sha256,
                    )
                    self.db.add(db_cert)
            
            # Generate CBOM entries
            cbom_entries = self.cbom_generator.generate(
                project_id=project.id,
                scan_id=scan.id,
                detections=all_detections,
                data_lifetime_years=project.data_lifetime_years,
                migration_time_years=project.migration_time_years,
                quantum_threat_horizon_years=10.0,  # From config
                business_criticality=project.business_criticality,
                exposure=project.exposure,
            )
            
            # Store crypto assets and findings
            for entry in cbom_entries:
                # Store asset
                asset = CryptoAsset(
                    project_id=project.id,
                    scan_id=scan.id,
                    algorithm=entry.detection.algorithm,
                    algorithm_family=entry.profile.family,
                    primitive_type=entry.profile.primitive_type,
                    key_size=entry.detection.key_size,
                    curve=entry.detection.curve,
                    mode=entry.detection.mode,
                    protocol=entry.detection.protocol,
                    library=entry.detection.library,
                    library_version=entry.detection.extra.get("library_version", ""),
                    file_path=entry.detection.file,
                    line=entry.detection.line,
                    language=entry.detection.language,
                    source_type=entry.detection.source_type,
                    evidence=entry.detection.evidence,
                    severity=entry.severity,
                    quantum_vulnerable=entry.profile.quantum_vulnerable,
                    recommendation=entry.recommendation,
                    classification=entry.classification,
                )
                self.db.add(asset)
                self.db.flush()
                
                # Store finding
                if entry.severity in {"HIGH", "CRITICAL"} or entry.profile.quantum_vulnerable:
                    pqc_advice = recommend(entry.detection.algorithm, entry.profile.primitive_type, entry.detection.key_size)
                    finding = Finding(
                        project_id=project.id,
                        scan_id=scan.id,
                        asset_id=asset.id,
                        title=f"{entry.detection.algorithm} detected - {entry.severity} severity",
                        algorithm=entry.detection.algorithm,
                        language=entry.detection.language,
                        file_path=entry.detection.file,
                        line=entry.detection.line,
                        evidence=entry.detection.evidence,
                        why_it_matters=pqc_advice.why_it_matters,
                        severity=entry.severity,
                        quantum_vulnerable=entry.profile.quantum_vulnerable,
                        risk_score=entry.risk_score,
                        recommendation=entry.recommendation,
                        migration_priority=entry.migration_priority,
                        remediation=pqc_advice.remediation,
                    )
                    self.db.add(finding)
            
            # Generate risk assessment
            self._generate_risk_assessment(project, scan)
            
            # Generate migration recommendations
            self._generate_migration_recommendations(project, scan, cbom_entries)
            
            # Update scan
            scan.status = "completed"
            scan.finished_at = datetime.utcnow()
            scan.progress = 100
            scan.files_scanned = len(all_detections)
            scan.findings_count = len(cbom_entries)
            self.db.commit()
            
        except Exception as e:
            scan.status = "failed"
            scan.error_message = str(e)
            scan.finished_at = datetime.utcnow()
            self.db.commit()
    
    def _generate_risk_assessment(self, project: Project, scan: Scan) -> None:
        """Generate overall risk assessment for project."""
        assets = self.db.query(CryptoAsset).filter(CryptoAsset.project_id == project.id).all()
        
        if not assets:
            return
        
        # Calculate overall score
        total_score = sum(
            self._calculate_asset_score(asset, project)
            for asset in assets
        )
        overall_score = total_score / len(assets) if assets else 0.0
        
        # Quantum readiness
        quantum_vulnerable = sum(1 for a in assets if a.quantum_vulnerable)
        quantum_readiness = ((len(assets) - quantum_vulnerable) / len(assets) * 100) if assets else 100.0
        
        # Mosca assessment
        mosca_result = assess_mosca(
            data_lifetime_years=project.data_lifetime_years,
            migration_time_years=project.migration_time_years,
            quantum_threat_horizon_years=10.0,
        )
        
        risk = RiskAssessment(
            project_id=project.id,
            scan_id=scan.id,
            overall_score=overall_score,
            category=self._category_for_score(overall_score),
            quantum_readiness_percent=quantum_readiness,
            quantum_threat_horizon_years=10.0,
            data_lifetime_years=project.data_lifetime_years,
            migration_time_years=project.migration_time_years,
            mosca_urgent=mosca_result.urgent,
            mosca_explanation=mosca_result.explanation,
            assumptions=mosca_result.assumptions,
        )
        self.db.add(risk)
    
    def _calculate_asset_score(self, asset: CryptoAsset, project: Project) -> float:
        """Calculate risk score for a single asset."""
        risk_inputs = RiskInputs(
            algorithm=asset.algorithm,
            key_size=asset.key_size,
            primitive_type=asset.primitive_type,
            data_lifetime_years=project.data_lifetime_years,
            migration_time_years=project.migration_time_years,
            quantum_threat_horizon_years=10.0,
            business_criticality=project.business_criticality,
            exposure=project.exposure,
        )
        score, _ = score_asset(risk_inputs)
        return score
    
    def _category_for_score(self, score: float) -> str:
        if score >= 75:
            return "CRITICAL"
        if score >= 50:
            return "HIGH"
        if score >= 25:
            return "MEDIUM"
        return "LOW"
    
    def _generate_migration_recommendations(self, project: Project, scan: Scan, cbom_entries: list[Any]) -> None:
        """Generate migration roadmap recommendations."""
        # Group by phase
        phases = {
            "discover": [],
            "prioritize": [],
            "prepare": [],
            "pilot": [],
            "migrate": [],
            "validate": [],
        }
        
        for entry in cbom_entries:
            if entry.migration_priority == "CRITICAL":
                phases["prioritize"].append(entry)
            elif entry.migration_priority == "HIGH":
                phases["prepare"].append(entry)
            elif entry.migration_priority == "MEDIUM":
                phases["pilot"].append(entry)
            else:
                phases["migrate"].append(entry)
        
        # Create recommendations
        for phase, entries in phases.items():
            for entry in entries[:10]:  # Limit per phase
                rec = MigrationRecommendation(
                    project_id=project.id,
                    asset_id=None,  # Can be linked later
                    phase=phase,
                    title=f"Migrate {entry.detection.algorithm} in {entry.detection.file}",
                    detail=f"Replace {entry.detection.algorithm} with {entry.pqc_candidate}",
                    pqc_candidate=entry.pqc_candidate,
                    migration_notes=entry.recommendation,
                    priority=entry.migration_priority,
                    status="planned",
                )
                self.db.add(rec)
