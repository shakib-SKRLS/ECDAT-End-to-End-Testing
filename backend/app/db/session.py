from collections.abc import Generator
from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import get_settings
from app.db.base import Base

_settings = get_settings()
connect_args = {"check_same_thread": False} if _settings.database_url.startswith("sqlite") else {}

# Ensure data directory exists for SQLite
if _settings.database_url.startswith("sqlite"):
    db_path = _settings.database_url.replace("sqlite:///", "")
    db_file = Path(db_path)
    db_file.parent.mkdir(parents=True, exist_ok=True)

engine = create_engine(_settings.database_url, future=True, connect_args=connect_args)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, expire_on_commit=False)


def get_db() -> Generator[Session, None, None]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db() -> None:
    Base.metadata.create_all(bind=engine)
