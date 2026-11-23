from typing import List
import threading

from fastapi import APIRouter, Depends, HTTPException, status, BackgroundTasks
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.models.entities import Scan
from app.schemas.api import ScanCreate, ScanOut
from app.services.scan_service import ScanService

router = APIRouter()


@router.post("", response_model=ScanOut, status_code=status.HTTP_201_CREATED)
def create_scan(scan: ScanCreate, background_tasks: BackgroundTasks, db: Session = Depends(get_db)):
    db_scan = Scan(
        project_id=scan.project_id,
        source_type=scan.source_type,
        source_location=scan.source_location,
        status="queued",
    )
    db.add(db_scan)
    db.commit()
    db.refresh(db_scan)
    
    # Execute scan in background. ScanService opens its own DB session: the
    # request-scoped `db` is closed when this response returns, so the
    # background task must not reuse it.
    background_tasks.add_task(ScanService().execute_scan, db_scan.id)
    
    return _to_out(db_scan)


@router.get("", response_model=List[ScanOut])
def list_scans(skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
    scans = db.query(Scan).order_by(Scan.created_at.desc()).offset(skip).limit(limit).all()
    return [_to_out(s) for s in scans]


@router.get("/{scan_id}", response_model=ScanOut)
def get_scan(scan_id: str, db: Session = Depends(get_db)):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return _to_out(scan)


@router.get("/{scan_id}/status")
def get_scan_status(scan_id: str, db: Session = Depends(get_db)):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return {"scan_id": scan.id, "status": scan.status, "progress": scan.progress}


def _to_out(scan: Scan) -> ScanOut:
    return ScanOut(
        id=scan.id,
        project_id=scan.project_id,
        status=scan.status,
        source_type=scan.source_type,
        source_location=scan.source_location,
        progress=scan.progress,
        files_scanned=scan.files_scanned,
        findings_count=scan.findings_count,
        error_message=scan.error_message,
        started_at=scan.started_at,
        finished_at=scan.finished_at,
        created_at=scan.created_at,
        is_demo=scan.is_demo,
    )
