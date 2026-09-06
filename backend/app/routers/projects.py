from typing import List

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.models.entities import Project, ProjectSource
from app.schemas.api import ProjectCreate, ProjectOut, ProjectSourceOut

router = APIRouter()


@router.post("", response_model=ProjectOut, status_code=status.HTTP_201_CREATED)
def create_project(project: ProjectCreate, db: Session = Depends(get_db)):
    db_project = Project(
        name=project.name,
        description=project.description,
        business_criticality=project.business_criticality,
        data_lifetime_years=project.data_lifetime_years,
        migration_time_years=project.migration_time_years,
        exposure=project.exposure,
    )
    db.add(db_project)
    db.commit()
    db.refresh(db_project)

    for source in project.sources:
        db_source = ProjectSource(
            project_id=db_project.id,
            source_type=source.source_type,
            location=source.location,
            label=source.label,
        )
        db.add(db_source)
    db.commit()

    return _to_out(db_project, db)


@router.get("", response_model=List[ProjectOut])
def list_projects(skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
    projects = db.query(Project).offset(skip).limit(limit).all()
    return [_to_out(p, db) for p in projects]


@router.get("/{project_id}", response_model=ProjectOut)
def get_project(project_id: str, db: Session = Depends(get_db)):
    project = db.query(Project).filter(Project.id == project_id).first()
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    return _to_out(project, db)


@router.delete("/{project_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_project(project_id: str, db: Session = Depends(get_db)):
    project = db.query(Project).filter(Project.id == project_id).first()
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    db.delete(project)
    db.commit()


def _to_out(project: Project, db: Session) -> ProjectOut:
    sources = db.query(ProjectSource).filter(ProjectSource.project_id == project.id).all()
    source_outs = [
        ProjectSourceOut(id=s.id, source_type=s.source_type, location=s.location, label=s.label)
        for s in sources
    ]
    return ProjectOut(
        id=project.id,
        name=project.name,
        description=project.description,
        business_criticality=project.business_criticality,
        data_lifetime_years=project.data_lifetime_years,
        migration_time_years=project.migration_time_years,
        exposure=project.exposure,
        created_at=project.created_at,
        sources=source_outs,
    )
