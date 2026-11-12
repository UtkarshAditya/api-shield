"""Stateless detector orchestration over safe features and baseline snapshots."""

from __future__ import annotations

import time
from datetime import datetime
from typing import Any, Mapping, MutableMapping

from ..features import TrafficFeatures
from .isolation_forest import IsolationForestDetector
from .results import DetectorResult
from .statistical import DetectorConfig, StatisticalDetector


class DetectionService:
    """Run statistical and optional Isolation Forest detectors without I/O."""

    def __init__(
        self,
        config: DetectorConfig | None = None,
        *,
        isolation_forest: IsolationForestDetector | None = None,
    ):
        self.statistical = StatisticalDetector(config)
        self.isolation_forest = isolation_forest

    def detect(
        self,
        features: TrafficFeatures,
        endpoint_baseline: Mapping[str, Any],
        *,
        caller_baseline: Mapping[str, Any] | None = None,
        all_baselines: Mapping[str, Any] | None = None,
        sequence_frequencies: Mapping[str, int] | None = None,
        previous_endpoint: str | None = None,
        timings_ns: MutableMapping[str, int] | None = None,
    ) -> list[DetectorResult]:
        """Evaluate applicable detectors for one feature record.

        ``caller_baseline`` is accepted for callers that need the contract
        available at orchestration time; current detectors use endpoint-level
        history and do not assume caller-specific aggregates exist.
        """
        del caller_baseline
        started = time.perf_counter_ns()
        results = self.statistical.detect(
            features,
            endpoint_baseline,
            all_baselines=all_baselines,
            sequence_frequencies=sequence_frequencies,
            previous_endpoint=previous_endpoint,
        )
        if timings_ns is not None:
            timings_ns["statistical_detection"] = (
                timings_ns.get("statistical_detection", 0)
                + time.perf_counter_ns()
                - started
            )
        if self.isolation_forest is not None:
            started = time.perf_counter_ns()
            results.append(
                self.isolation_forest.detect(
                    features,
                    baseline_ready=endpoint_baseline.get("state") == "active",
                )
            )
            if timings_ns is not None:
                timings_ns["isolation_forest_scoring"] = (
                    timings_ns.get("isolation_forest_scoring", 0)
                    + time.perf_counter_ns()
                    - started
                )
        return results


def parse_feature_timestamp(features: TrafficFeatures) -> datetime:
    """Parse feature timestamp for an ordered per-caller stream adapter."""
    return datetime.fromisoformat(features.ts.replace("Z", "+00:00"))
