"""Deterministic risk scoring. Weights are configurable; scores are inferred risk, not detections."""

from __future__ import annotations

from dataclasses import dataclass

from scanner.common.catalog import get_profile

SEVERITY_ORDER = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}

DEFAULT_WEIGHTS = {
    "algorithm": 1.0,
    "data_lifetime": 0.8,
    "migration": 0.8,
    "business_criticality": 1.0,
    "exposure": 0.7,
}


@dataclass
class RiskInputs:
    algorithm: str
    key_size: int | None
    primitive_type: str
    data_lifetime_years: float
    migration_time_years: float
    quantum_threat_horizon_years: float
    business_criticality: int  # 1-5
    exposure: str
    weights: dict[str, float] | None = None


def category_for_score(score: float) -> str:
    if score >= 75:
        return "CRITICAL"
    if score >= 50:
        return "HIGH"
    if score >= 25:
        return "MEDIUM"
    return "LOW"


def _key_size_modifier(algorithm: str, key_size: int | None) -> int:
    if key_size is None:
        return 0
    if algorithm == "RSA":
        if key_size < 2048:
            return 12
        if key_size == 2048:
            return 6
        if key_size >= 4096:
            return -4
    if algorithm == "AES":
        if key_size <= 128:
            return 6
        if key_size >= 256:
            return -4
    if algorithm in {"ECDSA", "ECDH", "ECC"} and key_size and key_size <= 256:
        return 4
    return 0


def _exposure_points(exposure: str) -> int:
    return {"public": 16, "internal": 8, "airgapped": 2}.get(exposure, 8)


def score_asset(inputs: RiskInputs) -> tuple[float, str]:
    profile = get_profile(inputs.algorithm)
    weights = inputs.weights or DEFAULT_WEIGHTS
    algorithm_risk = profile.baseline_algorithm_risk + _key_size_modifier(inputs.algorithm, inputs.key_size)
    lifetime_factor = min(20.0, inputs.data_lifetime_years * 2.0)
    if profile.quantum_vulnerable:
        overlap = inputs.data_lifetime_years + inputs.migration_time_years - inputs.quantum_threat_horizon_years
        migration_factor = 18.0 if overlap >= 0 else max(4.0, 12.0 + overlap)
    else:
        migration_factor = 4.0
    business = inputs.business_criticality * 4.0
    exposure = _exposure_points(inputs.exposure)

    raw = (
        algorithm_risk * weights["algorithm"]
        + lifetime_factor * weights["data_lifetime"]
        + migration_factor * weights["migration"]
        + business * weights["business_criticality"]
        + exposure * weights["exposure"]
    )
    # Theoretical max ~ 40+16+18+20+16 = 110 with default weights ~ 1
    score = max(0.0, min(100.0, raw * 0.85))
    if inputs.algorithm == "PrivateKeyMaterial":
        score = max(score, 88.0)
    if inputs.algorithm == "Library":
        score = min(score, 20.0)
    return round(score, 1), category_for_score(score)


def classify_asset(algorithm: str, quantum_vulnerable: bool, score: float) -> str:
    profile = get_profile(algorithm)
    if profile.family == "pqc" or algorithm in {"ML-KEM", "ML-DSA", "SLH-DSA"}:
        return "pqc_ready"
    if algorithm in {"AES", "ChaCha20", "ChaCha20-Poly1305", "SHA-256", "SHA-384", "SHA-512", "Argon2", "scrypt"}:
        if score < 50:
            return "acceptable"
    if quantum_vulnerable or algorithm in {"MD5", "SHA-1", "DES", "3DES", "SSL"}:
        return "vulnerable"
    if profile.family == "unknown" or algorithm in {"Library", "PrivateKeyMaterial"}:
        return "unknown"
    return "acceptable"
