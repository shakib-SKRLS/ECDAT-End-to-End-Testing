from typing import List

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.models.entities import CryptoAsset
from app.schemas.api import CryptoAssetOut

router = APIRouter()


@router.get("", response_model=List[CryptoAssetOut])
def list_assets(
    project_id: str | None = None,
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(get_db),
):
    query = db.query(CryptoAsset)
    if project_id:
        query = query.filter(CryptoAsset.project_id == project_id)
    assets = query.order_by(CryptoAsset.discovered_at.desc()).offset(skip).limit(limit).all()
    return [_to_out(a) for a in assets]


@router.get("/{asset_id}", response_model=CryptoAssetOut)
def get_asset(asset_id: str, db: Session = Depends(get_db)):
    asset = db.query(CryptoAsset).filter(CryptoAsset.id == asset_id).first()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    return _to_out(asset)


def _to_out(asset: CryptoAsset) -> CryptoAssetOut:
    return CryptoAssetOut(
        id=asset.id,
        project_id=asset.project_id,
        scan_id=asset.scan_id,
        algorithm=asset.algorithm,
        algorithm_family=asset.algorithm_family,
        primitive_type=asset.primitive_type,
        key_size=asset.key_size,
        curve=asset.curve,
        mode=asset.mode,
        protocol=asset.protocol,
        library=asset.library,
        library_version=asset.library_version,
        file=asset.file_path,
        line=asset.line,
        language=asset.language,
        source_type=asset.source_type,
        evidence=asset.evidence,
        severity=asset.severity,
        quantum_vulnerable=asset.quantum_vulnerable,
        recommendation=asset.recommendation,
        classification=asset.classification,
        discovered_at=asset.discovered_at,
    )
