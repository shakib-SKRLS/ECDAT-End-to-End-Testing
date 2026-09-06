from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field

Exposure = Literal["public", "internal", "airgapped"]
Severity = Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]
ScanStatus = Literal["queued", "running", "completed", "failed"]
SourceType = Literal["local_dir", "git", "archive"]


class ProjectSourceIn(BaseModel):
    source_type: SourceType
    location: str
    label: str = ""


class ProjectCreate(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    description: str = ""
    business_criticality: int = Field(default=3, ge=1, le=5)
    data_lifetime_years: float = Field(default=5.0, ge=0, le=100)
    migration_time_years: float = Field(default=3.0, ge=0, le=100)
    exposure: Exposure = "internal"
    sources: list[ProjectSourceIn] = Field(default_factory=list)


class ProjectSourceOut(ProjectSourceIn):
    id: str


class ProjectOut(BaseModel):
    id: str
    name: str
    description: str
    business_criticality: int
    data_lifetime_years: float
    migration_time_years: float
    exposure: str
    created_at: datetime
    sources: list[ProjectSourceOut] = Field(default_factory=list)


class ScanCreate(BaseModel):
    project_id: str
    source_type: SourceType = "local_dir"
    source_location: str = ""


class ScanOut(BaseModel):
    id: str
    project_id: str
    status: str
    source_type: str
    source_location: str
    progress: int
    files_scanned: int
    findings_count: int
    error_message: str
    started_at: datetime | None
    finished_at: datetime | None
    created_at: datetime
    is_demo: bool


class CryptoAssetOut(BaseModel):
    id: str
    project_id: str
    scan_id: str | None
    algorithm: str
    algorithm_family: str
    primitive_type: str
    key_size: int | None
    curve: str
    mode: str
    protocol: str
    library: str
    library_version: str
    file: str
    line: int | None
    language: str
    source_type: str
    evidence: str
    severity: str
    quantum_vulnerable: bool
    recommendation: str
    classification: str
    discovered_at: datetime


class FindingOut(BaseModel):
    id: str
    project_id: str
    scan_id: str | None
    asset_id: str | None
    title: str
    algorithm: str
    language: str
    file: str
    line: int | None
    evidence: str
    why_it_matters: str
    severity: str
    quantum_vulnerable: bool
    status: str
    risk_score: float
    recommendation: str
    migration_priority: str
    remediation: str
    created_at: datetime


class FindingStatusUpdate(BaseModel):
    status: Literal["open", "in_progress", "accepted_risk", "resolved"]


class CertificateOut(BaseModel):
    id: str
    project_id: str
    file: str
    subject: str
    issuer: str
    serial_number: str
    not_before: datetime | None
    not_after: datetime | None
    signature_algorithm: str
    public_key_algorithm: str
    key_size: int | None
    curve: str
    san: str
    expired: bool
    fingerprint_sha256: str


class RiskOut(BaseModel):
    id: str
    project_id: str
    overall_score: float
    category: str
    quantum_readiness_percent: float
    quantum_threat_horizon_years: float
    data_lifetime_years: float
    migration_time_years: float
    mosca_urgent: bool
    mosca_explanation: str
    assumptions: str
    created_at: datetime
    low: int = 0
    medium: int = 0
    high: int = 0
    critical: int = 0


class RecommendationOut(BaseModel):
    id: str
    project_id: str
    asset_id: str | None
    phase: str
    title: str
    detail: str
    pqc_candidate: str
    migration_notes: str
    priority: str
    status: str


class MigrationPlanOut(BaseModel):
    project_id: str
    phases: dict[str, list[RecommendationOut]]
    tasks: list[RecommendationOut]


class DashboardOut(BaseModel):
    project_id: str | None
    total_projects: int
    crypto_assets: int
    quantum_vulnerable_assets: int
    critical_findings: int
    pqc_ready_assets: int
    migration_progress_percent: float
    quantum_readiness_percent: float
    risk_distribution: dict[str, int]
    algorithm_distribution: dict[str, int]
    top_findings: list[FindingOut]
    mosca: RiskOut | None = None
    dependency_rows: list[dict[str, str]] = Field(default_factory=list)


class SettingsOut(BaseModel):
    quantum_threat_horizon_years: float
    default_data_lifetime_years: float
    default_migration_time_years: float
    max_scan_files: int
    max_file_bytes: int


class SettingsUpdate(BaseModel):
    quantum_threat_horizon_years: float | None = Field(default=None, ge=1, le=50)


class HealthOut(BaseModel):
    status: str
    service: str
    version: str
    database: str
