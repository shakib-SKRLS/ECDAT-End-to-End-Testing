from typing import List

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.models.entities import Finding
from app.schemas.api import FindingOut, FindingStatusUpdate

router = APIRouter()


@router.get("", response_model=List[FindingOut])
def list_findings(
    project_id: str | None = None,
    severity: str | None = None,
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(get_db),
):
    query = db.query(Finding)
    if project_id:
        query = query.filter(Finding.project_id == project_id)
    if severity:
        query = query.filter(Finding.severity == severity.upper())
    findings = query.order_by(Finding.created_at.desc()).offset(skip).limit(limit).all()
    return [_to_out(f) for f in findings]


@router.get("/{finding_id}", response_model=FindingOut)
def get_finding(finding_id: str, db: Session = Depends(get_db)):
    finding = db.query(Finding).filter(Finding.id == finding_id).first()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    return _to_out(finding)


@router.patch("/{finding_id}", response_model=FindingOut)
def update_finding_status(finding_id: str, update: FindingStatusUpdate, db: Session = Depends(get_db)):
    finding = db.query(Finding).filter(Finding.id == finding_id).first()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    finding.status = update.status
    db.commit()
    db.refresh(finding)
    return _to_out(finding)


def _to_out(finding: Finding) -> FindingOut:
    return FindingOut(
        id=finding.id,
        project_id=finding.project_id,
        scan_id=finding.scan_id,
        asset_id=finding.asset_id,
        title=finding.title,
        algorithm=finding.algorithm,
        language=finding.language,
        file=finding.file_path,
        line=finding.line,
        evidence=finding.evidence,
        why_it_matters=finding.why_it_matters,
        severity=finding.severity,
        quantum_vulnerable=finding.quantum_vulnerable,
        status=finding.status,
        risk_score=finding.risk_score,
        recommendation=finding.recommendation,
        migration_priority=finding.migration_priority,
        remediation=finding.remediation,
        created_at=finding.created_at,
    )
