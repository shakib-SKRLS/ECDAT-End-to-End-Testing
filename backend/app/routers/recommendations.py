from typing import List

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.models.entities import MigrationRecommendation
from app.schemas.api import RecommendationOut, MigrationPlanOut

router = APIRouter()


@router.get("/project/{project_id}", response_model=List[RecommendationOut])
def get_project_recommendations(project_id: str, db: Session = Depends(get_db)):
    recommendations = (
        db.query(MigrationRecommendation)
        .filter(MigrationRecommendation.project_id == project_id)
        .order_by(MigrationRecommendation.priority.desc())
        .all()
    )
    return [_to_out(r) for r in recommendations]


@router.get("/{recommendation_id}", response_model=RecommendationOut)
def get_recommendation(recommendation_id: str, db: Session = Depends(get_db)):
    rec = db.query(MigrationRecommendation).filter(MigrationRecommendation.id == recommendation_id).first()
    if not rec:
        raise HTTPException(status_code=404, detail="Recommendation not found")
    return _to_out(rec)


@router.get("/project/{project_id}/roadmap", response_model=MigrationPlanOut)
def get_migration_roadmap(project_id: str, db: Session = Depends(get_db)):
    recommendations = (
        db.query(MigrationRecommendation)
        .filter(MigrationRecommendation.project_id == project_id)
        .order_by(MigrationRecommendation.priority.desc())
        .all()
    )
    
    phases = {}
    for rec in recommendations:
        if rec.phase not in phases:
            phases[rec.phase] = []
        phases[rec.phase].append(_to_out(rec))
    
    return MigrationPlanOut(
        project_id=project_id,
        phases=phases,
        tasks=[_to_out(r) for r in recommendations],
    )


def _to_out(rec: MigrationRecommendation) -> RecommendationOut:
    return RecommendationOut(
        id=rec.id,
        project_id=rec.project_id,
        asset_id=rec.asset_id,
        phase=rec.phase,
        title=rec.title,
        detail=rec.detail,
        pqc_candidate=rec.pqc_candidate,
        migration_notes=rec.migration_notes,
        priority=rec.priority,
        status=rec.status,
    )
