"""Mosca-inspired urgency: compare confidentiality lifetime + migration time against a configurable horizon.

This is NOT a prediction of when a cryptographically relevant quantum computer will exist.
X is an administrator-configured planning assumption.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class MoscaResult:
    x_threat_horizon_years: float
    y_data_lifetime_years: float
    z_migration_time_years: float
    urgent: bool
    window_years: float
    slack_years: float
    explanation: str
    assumptions: str


def assess_mosca(
    data_lifetime_years: float,
    migration_time_years: float,
    quantum_threat_horizon_years: float,
) -> MoscaResult:
    y = data_lifetime_years
    z = migration_time_years
    x = quantum_threat_horizon_years
    window = y + z
    slack = x - window
    urgent = window >= x
    if urgent:
        explanation = (
            f"Urgency is HIGH under the configured assumption: data lifetime (Y={y:g}y) plus "
            f"migration time (Z={z:g}y) is {window:g} years, which is not less than the "
            f"configured quantum-threat horizon (X={x:g}y). The migration window overlaps "
            f"or exceeds the planning horizon."
        )
    else:
        explanation = (
            f"Under the configured assumption, Y+Z={window:g} years is still below X={x:g} years "
            f"(slack {slack:g} years). This is a planning indicator only — shortening X, lengthening "
            f"data lifetime, or slower migration can reverse the result."
        )
    assumptions = (
        "X is a configurable planning horizon, not a forecast of quantum-computer arrival. "
        "Y is estimated confidentiality lifetime of protected data. "
        "Z is estimated time to complete cryptographic migration. "
        "Detected algorithms are facts; Mosca urgency is an inferred assessment from these assumptions."
    )
    return MoscaResult(
        x_threat_horizon_years=x,
        y_data_lifetime_years=y,
        z_migration_time_years=z,
        urgent=urgent,
        window_years=window,
        slack_years=slack,
        explanation=explanation,
        assumptions=assumptions,
    )
