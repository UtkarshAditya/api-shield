"""Shared result type for anomaly indicators and suspicious signals."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any


@dataclass(frozen=True)
class DetectorResult:
    """Serializable detector result; anomaly indicators never confirm attacks."""

    detector: str
    detected: bool
    kind: str
    score: float
    severity: str
    observed: Any
    expected: Any
    threshold: Any
    explanation: str
    contributing_features: tuple[str, ...]
    baseline_ready: bool
    timestamp: str
    confirmed_attack: bool = False

    def to_dict(self) -> dict[str, Any]:
        """Return JSON-compatible result data."""
        result = asdict(self)
        result["contributing_features"] = list(self.contributing_features)
        return result
