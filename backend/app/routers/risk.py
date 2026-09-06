from typing import List

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.models.entities import RiskAssessment, Finding
from app.schemas.api import RiskOut

router = APIRouter()


@router.get("/project/{project_id}", response_model=RiskOut)
def get_project_risk(project_id: str, db: Session = Depends(get_db)):
    risk = (
        db.query(RiskAssessment)
        .filter(RiskAssessment.project_id == project_id)
        .order_by(RiskAssessment.created_at.desc())
        .first()
    )
    if not risk:
        raise HTTPException(status_code=404, detail="Risk assessment not found")
    
    # Count findings by severity
    findings = db.query(Finding).filter(Finding.project_id == project_id).all()
    low = sum(1 for f in findings if f.severity == "LOW")
    medium = sum(1 for f in findings if f.severity == "MEDIUM")
    high = sum(1 for f in findings if f.severity == "HIGH")
    critical = sum(1 for f in findings if f.severity == "CRITICAL")
    
    return _to_out(risk, low, medium, high, critical)


def _to_out(risk: RiskAssessment, low: int, medium: int, high: int, critical: int) -> RiskOut:
    return RiskOut(
        id=risk.id,
        project_id=risk.project_id,
        overall_score=risk.overall_score,
        category=risk.category,
        quantum_readiness_percent=risk.quantum_readiness_percent,
        quantum_threat_horizon_years=risk.quantum_threat_horizon_years,
        data_lifetime_years=risk.data_lifetime_years,
        migration_time_years=risk.migration_time_years,
        mosca_urgent=risk.mosca_urgent,
        mosca_explanation=risk.mosca_explanation,
        assumptions=risk.assumptions,
        created_at=risk.created_at,
        low=low,
        medium=medium,
        high=high,
        critical=critical,
    )
