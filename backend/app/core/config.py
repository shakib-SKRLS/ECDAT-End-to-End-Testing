from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


REPO_ROOT = Path(__file__).resolve().parents[3]


class Settings(BaseSettings):
    # .env lives at the repo root (README step 4); resolve it absolutely so
    # it is found whether the backend runs from backend/ or the repo root.
    model_config = SettingsConfigDict(
        env_prefix="ECDAT_", env_file=str(REPO_ROOT / ".env"), extra="ignore"
    )

    database_url: str = "sqlite:///./data/ecdat.db"
    host: str = "0.0.0.0"
    port: int = 8000
    cors_origins: str = "http://localhost:3000,http://127.0.0.1:3000,http://localhost:5173,http://127.0.0.1:5173,http://localhost:8080"

    allowed_scan_roots: str = ""
    quantum_threat_horizon_years: float = 10.0
    default_data_lifetime_years: float = 5.0
    default_migration_time_years: float = 3.0

    max_scan_files: int = 20_000
    max_file_bytes: int = 1_048_576
    scan_workers: int = 8
    git_clone_timeout_seconds: int = 120
    clone_root: str = "./data/clones"

    log_level: str = "INFO"

    @property
    def cors_origin_list(self) -> list[str]:
        return [item.strip() for item in self.cors_origins.split(",") if item.strip()]

    def scan_roots(self) -> list[Path]:
        configured = [Path(p).resolve() for p in self.allowed_scan_roots.split(",") if p.strip()]
        defaults = [
            REPO_ROOT,
            (REPO_ROOT / "sample-data").resolve(),
            Path("./data").resolve(),
        ]
        roots = configured or defaults
        return roots


@lru_cache
def get_settings() -> Settings:
    return Settings()
