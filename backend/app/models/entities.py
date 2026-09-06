from datetime import datetime
from uuid import uuid4

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base


def _uuid() -> str:
    return str(uuid4())


class Project(Base):
    __tablename__ = "projects"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    description: Mapped[str] = mapped_column(Text, default="")
    business_criticality: Mapped[int] = mapped_column(Integer, default=3)  # 1-5
    data_lifetime_years: Mapped[float] = mapped_column(Float, default=5.0)
    migration_time_years: Mapped[float] = mapped_column(Float, default=3.0)
    exposure: Mapped[str] = mapped_column(String(32), default="internal")  # public/internal/airgapped
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    sources: Mapped[list["ProjectSource"]] = relationship(back_populates="project", cascade="all, delete-orphan")
    scans: Mapped[list["Scan"]] = relationship(back_populates="project", cascade="all, delete-orphan")
    assets: Mapped[list["CryptoAsset"]] = relationship(back_populates="project", cascade="all, delete-orphan")
    findings: Mapped[list["Finding"]] = relationship(back_populates="project", cascade="all, delete-orphan")
    certificates: Mapped[list["Certificate"]] = relationship(back_populates="project", cascade="all, delete-orphan")
    risk_assessments: Mapped[list["RiskAssessment"]] = relationship(back_populates="project", cascade="all, delete-orphan")
    recommendations: Mapped[list["MigrationRecommendation"]] = relationship(
        back_populates="project", cascade="all, delete-orphan"
    )


class ProjectSource(Base):
    __tablename__ = "project_sources"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    project_id: Mapped[str] = mapped_column(ForeignKey("projects.id"), nullable=False)
    source_type: Mapped[str] = mapped_column(String(32), nullable=False)  # local_dir, git, archive
    location: Mapped[str] = mapped_column(Text, nullable=False)
    label: Mapped[str] = mapped_column(String(200), default="")

    project: Mapped[Project] = relationship(back_populates="sources")


class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    project_id: Mapped[str] = mapped_column(ForeignKey("projects.id"), nullable=False)
    status: Mapped[str] = mapped_column(String(32), default="queued")
    source_type: Mapped[str] = mapped_column(String(32), default="local_dir")
    source_location: Mapped[str] = mapped_column(Text, default="")
    progress: Mapped[int] = mapped_column(Integer, default=0)
    files_scanned: Mapped[int] = mapped_column(Integer, default=0)
    findings_count: Mapped[int] = mapped_column(Integer, default=0)
    error_message: Mapped[str] = mapped_column(Text, default="")
    started_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    is_demo: Mapped[bool] = mapped_column(Boolean, default=False)

    project: Mapped[Project] = relationship(back_populates="scans")
    assets: Mapped[list["CryptoAsset"]] = relationship(back_populates="scan")
    findings: Mapped[list["Finding"]] = relationship(back_populates="scan")


class CryptoAsset(Base):
    __tablename__ = "crypto_assets"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    project_id: Mapped[str] = mapped_column(ForeignKey("projects.id"), nullable=False)
    scan_id: Mapped[str | None] = mapped_column(ForeignKey("scans.id"), nullable=True)
    algorithm: Mapped[str] = mapped_column(String(64), nullable=False)
    algorithm_family: Mapped[str] = mapped_column(String(64), default="")
    primitive_type: Mapped[str] = mapped_column(String(64), default="")
    key_size: Mapped[int | None] = mapped_column(Integer, nullable=True)
    curve: Mapped[str] = mapped_column(String(64), default="")
    mode: Mapped[str] = mapped_column(String(64), default="")
    protocol: Mapped[str] = mapped_column(String(64), default="")
    library: Mapped[str] = mapped_column(String(128), default="")
    library_version: Mapped[str] = mapped_column(String(64), default="")
    file_path: Mapped[str] = mapped_column(Text, default="")
    line: Mapped[int | None] = mapped_column(Integer, nullable=True)
    language: Mapped[str] = mapped_column(String(32), default="")
    source_type: Mapped[str] = mapped_column(String(32), default="source")
    evidence: Mapped[str] = mapped_column(Text, default="")
    severity: Mapped[str] = mapped_column(String(16), default="MEDIUM")
    quantum_vulnerable: Mapped[bool] = mapped_column(Boolean, default=False)
    recommendation: Mapped[str] = mapped_column(Text, default="")
    classification: Mapped[str] = mapped_column(String(32), default="unknown")
    discovered_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    project: Mapped[Project] = relationship(back_populates="assets")
    scan: Mapped[Scan | None] = relationship(back_populates="assets")
    findings: Mapped[list["Finding"]] = relationship(back_populates="asset")


class Finding(Base):
    __tablename__ = "findings"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    project_id: Mapped[str] = mapped_column(ForeignKey("projects.id"), nullable=False)
    scan_id: Mapped[str | None] = mapped_column(ForeignKey("scans.id"), nullable=True)
    asset_id: Mapped[str | None] = mapped_column(ForeignKey("crypto_assets.id"), nullable=True)
    title: Mapped[str] = mapped_column(String(300), nullable=False)
    algorithm: Mapped[str] = mapped_column(String(64), default="")
    language: Mapped[str] = mapped_column(String(32), default="")
    file_path: Mapped[str] = mapped_column(Text, default="")
    line: Mapped[int | None] = mapped_column(Integer, nullable=True)
    evidence: Mapped[str] = mapped_column(Text, default="")
    why_it_matters: Mapped[str] = mapped_column(Text, default="")
    severity: Mapped[str] = mapped_column(String(16), default="MEDIUM")
    quantum_vulnerable: Mapped[bool] = mapped_column(Boolean, default=False)
    status: Mapped[str] = mapped_column(String(32), default="open")
    risk_score: Mapped[float] = mapped_column(Float, default=0.0)
    recommendation: Mapped[str] = mapped_column(Text, default="")
    migration_priority: Mapped[str] = mapped_column(String(16), default="MEDIUM")
    remediation: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    project: Mapped[Project] = relationship(back_populates="findings")
    scan: Mapped[Scan | None] = relationship(back_populates="findings")
    asset: Mapped[CryptoAsset | None] = relationship(back_populates="findings")


class Certificate(Base):
    __tablename__ = "certificates"
    __table_args__ = (UniqueConstraint("project_id", "fingerprint_sha256", name="uq_cert_fp"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    project_id: Mapped[str] = mapped_column(ForeignKey("projects.id"), nullable=False)
    scan_id: Mapped[str | None] = mapped_column(ForeignKey("scans.id"), nullable=True)
    file_path: Mapped[str] = mapped_column(Text, default="")
    subject: Mapped[str] = mapped_column(Text, default="")
    issuer: Mapped[str] = mapped_column(Text, default="")
    serial_number: Mapped[str] = mapped_column(String(128), default="")
    not_before: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    not_after: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    signature_algorithm: Mapped[str] = mapped_column(String(128), default="")
    public_key_algorithm: Mapped[str] = mapped_column(String(64), default="")
    key_size: Mapped[int | None] = mapped_column(Integer, nullable=True)
    curve: Mapped[str] = mapped_column(String(64), default="")
    san: Mapped[str] = mapped_column(Text, default="")
    expired: Mapped[bool] = mapped_column(Boolean, default=False)
    fingerprint_sha256: Mapped[str] = mapped_column(String(64), default="")

    project: Mapped[Project] = relationship(back_populates="certificates")


class RiskAssessment(Base):
    __tablename__ = "risk_assessments"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    project_id: Mapped[str] = mapped_column(ForeignKey("projects.id"), nullable=False)
    scan_id: Mapped[str | None] = mapped_column(ForeignKey("scans.id"), nullable=True)
    overall_score: Mapped[float] = mapped_column(Float, default=0.0)
    category: Mapped[str] = mapped_column(String(16), default="LOW")
    quantum_readiness_percent: Mapped[float] = mapped_column(Float, default=0.0)
    quantum_threat_horizon_years: Mapped[float] = mapped_column(Float, default=10.0)
    data_lifetime_years: Mapped[float] = mapped_column(Float, default=5.0)
    migration_time_years: Mapped[float] = mapped_column(Float, default=3.0)
    mosca_urgent: Mapped[bool] = mapped_column(Boolean, default=False)
    mosca_explanation: Mapped[str] = mapped_column(Text, default="")
    assumptions: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    project: Mapped[Project] = relationship(back_populates="risk_assessments")


class MigrationRecommendation(Base):
    __tablename__ = "migration_recommendations"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    project_id: Mapped[str] = mapped_column(ForeignKey("projects.id"), nullable=False)
    asset_id: Mapped[str | None] = mapped_column(ForeignKey("crypto_assets.id"), nullable=True)
    phase: Mapped[str] = mapped_column(String(32), default="discover")
    title: Mapped[str] = mapped_column(String(300), nullable=False)
    detail: Mapped[str] = mapped_column(Text, default="")
    pqc_candidate: Mapped[str] = mapped_column(String(128), default="")
    migration_notes: Mapped[str] = mapped_column(Text, default="")
    priority: Mapped[str] = mapped_column(String(16), default="MEDIUM")
    status: Mapped[str] = mapped_column(String(32), default="planned")

    project: Mapped[Project] = relationship(back_populates="recommendations")


class AppSetting(Base):
    __tablename__ = "app_settings"

    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    value: Mapped[str] = mapped_column(Text, default="")
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
