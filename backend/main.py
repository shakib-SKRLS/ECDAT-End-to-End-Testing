import sys
from contextlib import asynccontextmanager
from pathlib import Path

# Add parent directory to path to import scanner module
sys.path.insert(0, str(Path(__file__).parent.parent))

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from app.core.config import get_settings
from app.core.errors import AppError, app_error_handler, http_error_handler
from app.db.session import engine, init_db
from app.routers import projects, scans, assets, findings, risk, recommendations

settings = get_settings()


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    init_db()
    yield
    # Shutdown
    pass


app = FastAPI(
    title="ECDAT API",
    description="Enterprise Cryptographic Discovery & Analysis Tool",
    version="0.1.0",
    lifespan=lifespan,
)

# Handlers defined in app.core.errors — without these, AppError (e.g. the
# 400/403s from app.core.security) surfaces as an unhandled 500.
app.add_exception_handler(AppError, app_error_handler)
app.add_exception_handler(HTTPException, http_error_handler)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origin_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(projects.router, prefix="/api/projects", tags=["projects"])
app.include_router(scans.router, prefix="/api/scans", tags=["scans"])
app.include_router(assets.router, prefix="/api/assets", tags=["assets"])
app.include_router(findings.router, prefix="/api/findings", tags=["findings"])
app.include_router(risk.router, prefix="/api/risk", tags=["risk"])
app.include_router(recommendations.router, prefix="/api/recommendations", tags=["recommendations"])


@app.get("/")
async def root():
    return {"message": "ECDAT API", "version": "0.1.0"}


@app.get("/health")
async def health():
    return {"status": "healthy"}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "main:app",
        host=settings.host,
        port=settings.port,
        reload=True,
    )
