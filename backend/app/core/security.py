from __future__ import annotations

import logging
import os
from pathlib import Path

from app.core.config import get_settings
from app.core.errors import AppError

logger = logging.getLogger("ecdat.security")

PRIVATE_KEY_MARKERS = (
    "BEGIN PRIVATE KEY",
    "BEGIN RSA PRIVATE KEY",
    "BEGIN EC PRIVATE KEY",
    "BEGIN OPENSSH PRIVATE KEY",
    "BEGIN DSA PRIVATE KEY",
    "BEGIN ENCRYPTED PRIVATE KEY",
)


def looks_like_private_key(text: str) -> bool:
    upper = text.upper()
    return any(marker in upper for marker in PRIVATE_KEY_MARKERS)


def redact_secrets(text: str, limit: int = 240) -> str:
    """Return evidence-safe snippet; never keep PEM private key bodies."""
    if looks_like_private_key(text):
        return "[redacted: private key material omitted]"
    cleaned = " ".join(text.split())
    return cleaned[:limit]


def resolve_allowed_path(user_path: str) -> Path:
    settings = get_settings()
    candidate = Path(user_path).expanduser().resolve()
    if not candidate.exists():
        raise AppError(f"Path does not exist: {candidate}", code="path_not_found", status_code=400)
    roots = settings.scan_roots()
    for root in roots:
        try:
            candidate.relative_to(root)
            return candidate
        except ValueError:
            continue
    raise AppError(
        "Scan path is outside allowed scan roots. Configure ECDAT_ALLOWED_SCAN_ROOTS to expand access.",
        code="path_not_allowed",
        status_code=403,
    )


def safe_join(base: Path, *parts: str) -> Path:
    """Prevent zip-slip / path traversal when extracting archives."""
    target = (base / Path(*parts)).resolve()
    try:
        target.relative_to(base.resolve())
    except ValueError as exc:
        raise AppError("Archive path traversal blocked", code="zip_slip", status_code=400) from exc
    return target


def validate_git_url(url: str) -> str:
    url = url.strip()
    if not url:
        raise AppError("Git URL is required", code="invalid_git_url")
    lowered = url.lower()
    if lowered.startswith("file:"):
        raise AppError("file:// git URLs are not allowed", code="invalid_git_url", status_code=400)
    allowed_prefixes = ("https://", "http://", "git://", "ssh://", "git@")
    if not any(url.startswith(prefix) or lowered.startswith(prefix) for prefix in allowed_prefixes):
        raise AppError("Unsupported git URL scheme", code="invalid_git_url", status_code=400)
    if any(token in url for token in (";", "|", "&", "`", "$", "\n", "\r")):
        raise AppError("Git URL contains unsafe characters", code="invalid_git_url", status_code=400)
    return url


def ensure_data_dirs() -> None:
    settings = get_settings()
    Path("./data").mkdir(parents=True, exist_ok=True)
    Path(settings.clone_root).mkdir(parents=True, exist_ok=True)
    os.environ.setdefault("GIT_TERMINAL_PROMPT", "0")
