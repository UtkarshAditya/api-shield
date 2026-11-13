"""Live learner: Redis stream -> features -> baselines + detectors -> alerts in the Admin DB.

Per record it mirrors ``ReplayEvaluator.evaluate`` (replay.py):

    baseline.get_endpoint_baseline / get_all_baselines / get_sequence_frequencies
    -> DetectionService.detect(..., previous_endpoint)   (previous endpoint per caller)
    -> AlertService.generate_alerts(results, features)
    -> baseline.update(features, trusted=not predicted_anomaly)
    -> isolation_forest.observe(...) when accepted and the endpoint is active

and adds the Admin integration around it (configuration only, no detector math):

* sensitivity: ``learning_state.sensitivity`` s in [0, 1] scales the statistical
  thresholds by (1.5 - s): 0.5 (default) keeps the M3 defaults (z 3.0, rate ratio 3.0),
  1.0 halves them (more alerts), 0.0 multiplies them by 1.5 (fewer alerts).
* analyst feedback: a false positive on a reason raises that detector's thresholds with
  the existing suggestion rule (feedback._map_numeric_threshold with
  FeedbackAnalysisConfig.suggested_threshold_increase, i.e. +10 %). The adjusted detector
  is evaluated by the M3 StatisticalDetector itself, built with the adjusted config.
  Signal detectors with no numeric threshold (rule hits, new shape, ...) are not changed;
  the applied delta (0.1 or 0.0) is written back to alert_feedback.threshold_delta.
* endpoint risk: the latest finished scan's endpoint_risk (0-10, keyed by path) / 10.
* threshold profile: APISHIELD_LEARNING_THRESHOLD_MULTIPLIERS ("latency=3,request_size=2")
  scales single detectors the same way feedback does (deployment config, e.g. a laptop demo
  where localhost latency jitter is not a signal). Feedback multipliers stack on top.
* warm-up: done the first time every endpoint with accepted normal traffic is active; it stays
  done (persisted) until a reset. Endpoints first seen later are learned in the background and
  do not send the whole learner back to warm-up.
* mode=disabled (Admin): keep learning, create no alerts. reset_requested_at: drop
  baselines and models and warm up again.
"""

from __future__ import annotations

import asyncio
import logging
import os
import time
from collections import OrderedDict
from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Mapping

from .alert_mapping import DETECTOR_LABELS, detector_for_label, parse_ts
from .alerts import Alert, AlertConfig, AlertService
from .baselines import ACTIVE, BaselineConfig, BaselineLearner
from .consumer import FeatureEnvelope
from .detectors.isolation_forest import InMemoryModelStore, IsolationForestConfig, IsolationForestDetector
from .detectors.results import DetectorResult
from .detectors.service import DetectionService
from .detectors.statistical import DetectorConfig, StatisticalDetector
from .feedback import FeedbackAnalysisConfig, FeedbackService, _map_numeric_threshold
from .features import TrafficFeatures
from .sql_storage import SqlLearningStorage

log = logging.getLogger("apishield.learning.live")

NUMERIC_DETECTORS = ("request_rate_spike", "request_size", "response_size", "latency", "http_error_rate")
_PREVIOUS_ENDPOINT_CACHE = 10_000


def _env_bool(env: Mapping[str, str], name: str, default: bool) -> bool:
    value = env.get(name)
    return default if value is None else value.strip().lower() in ("1", "true", "yes", "on")


@dataclass(frozen=True)
class LiveSettings:
    """Live-runner settings. Baseline tuning comes from BaselineConfig.from_env()."""

    upstream_id: str = "up_shop"
    database_url: str = "sqlite:///./admin_api.db"
    isolation_forest: bool = True
    if_min_samples: int = 100          # IsolationForestConfig default
    detector_min_samples: int = 5      # DetectorConfig default
    max_event_age_seconds: float = 300.0  # older events (stream history) train, never alert
    alert_during_warmup: bool = True   # False: no alerts until warm-up is done
    threshold_profile: tuple[tuple[str, float], ...] = ()
    housekeeping_seconds: float = 2.0
    baseline_flush_seconds: float = 5.0
    risk_cache_seconds: float = 30.0

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> "LiveSettings":
        e = os.environ if env is None else env
        return cls(
            upstream_id=e.get("APISHIELD_UPSTREAM_ID", cls.upstream_id),
            database_url=e.get("ADMIN_DATABASE_URL", cls.database_url),
            isolation_forest=_env_bool(e, "APISHIELD_LEARNING_ISOLATION_FOREST", cls.isolation_forest),
            if_min_samples=int(e.get("APISHIELD_LEARNING_IF_MIN_SAMPLES", cls.if_min_samples)),
            detector_min_samples=int(e.get("APISHIELD_LEARNING_DETECTOR_MIN_SAMPLES", cls.detector_min_samples)),
            max_event_age_seconds=float(e.get("APISHIELD_LEARNING_MAX_EVENT_AGE_SECONDS",
                                              cls.max_event_age_seconds)),
            alert_during_warmup=_env_bool(e, "APISHIELD_LEARNING_ALERT_DURING_WARMUP", cls.alert_during_warmup),
            threshold_profile=_parse_profile(e.get("APISHIELD_LEARNING_THRESHOLD_MULTIPLIERS", "")),
            housekeeping_seconds=float(e.get("APISHIELD_LEARNING_STATE_SECONDS", cls.housekeeping_seconds)),
            baseline_flush_seconds=float(e.get("APISHIELD_LEARNING_FLUSH_SECONDS", cls.baseline_flush_seconds)),
            risk_cache_seconds=float(e.get("APISHIELD_LEARNING_RISK_CACHE_SECONDS", cls.risk_cache_seconds)),
        )


def _parse_profile(raw: str) -> tuple[tuple[str, float], ...]:
    out = []
    for part in raw.split(","):
        if not part.strip():
            continue
        name, _, value = part.partition("=")
        name = name.strip()
        if name not in NUMERIC_DETECTORS:
            raise ValueError(f"APISHIELD_LEARNING_THRESHOLD_MULTIPLIERS: {name!r} is not one of {NUMERIC_DETECTORS}")
        factor = float(value)
        if factor <= 0:
            raise ValueError("APISHIELD_LEARNING_THRESHOLD_MULTIPLIERS: factors must be positive")
        out.append((name, factor))
    return tuple(out)


class SqlEndpointRiskProvider:
    """M2 endpoint risk from the latest finished scan (0-10 -> 0-1). The scanner keys by
    path, so the method is ignored. Cached for ``ttl`` seconds."""

    def __init__(self, storage: SqlLearningStorage, ttl: float = 30.0,
                 clock: Callable[[], float] = time.monotonic) -> None:
        self.storage, self.ttl, self._clock = storage, ttl, clock
        self._risk: dict[str, float] = {}
        self._loaded_at: float | None = None
        self._scan_id: str | None = None

    def get_risk_score(self, endpoint: str, method: str) -> float | None:
        del method
        now = self._clock()
        if self._loaded_at is None or now - self._loaded_at >= self.ttl:
            try:
                self._risk = self.storage.latest_endpoint_risk()
            except Exception as exc:  # keep the last known values
                log.warning("endpoint risk refresh failed: %s", type(exc).__name__)
            self._loaded_at = now
        value = self._risk.get(endpoint)
        if not isinstance(value, (int, float)) or isinstance(value, bool):
            return None
        return max(0.0, min(1.0, float(value) / 10.0))

    def invalidate(self) -> None:
        self._loaded_at = None

    def refresh_if_new_scan(self) -> bool:
        """Called from housekeeping: a newly finished scan is picked up within seconds."""
        scan_id = self.storage.latest_scan_id()
        if scan_id == self._scan_id:
            return False
        self._scan_id = scan_id
        self.invalidate()
        return True


class TunedDetection:
    """DetectionService with Admin sensitivity and per-detector feedback multipliers.

    The base run uses the sensitivity-scaled config. A detector with a feedback multiplier
    is re-evaluated by a StatisticalDetector built with its own scaled config, and its
    result replaces the base one. No detector logic is reimplemented here.
    """

    def __init__(self, base: DetectorConfig, isolation_forest: IsolationForestDetector | None) -> None:
        self.base = base
        self.isolation_forest = isolation_forest
        self.sensitivity = 0.5
        self.profile: dict[str, float] = {}       # deployment config
        self.multipliers: dict[str, float] = {}   # analyst feedback
        self._rebuild()

    def _factor(self, detector: str) -> float:
        return self.profile.get(detector, 1.0) * self.multipliers.get(detector, 1.0)

    def _config(self, multiplier: float = 1.0) -> DetectorConfig:
        scale = (1.5 - self.sensitivity) * multiplier
        return replace(
            self.base,
            z_score_threshold=self.base.z_score_threshold * scale,
            request_rate_ratio_threshold=max(1.05, self.base.request_rate_ratio_threshold * scale),
        )

    def _rebuild(self) -> None:
        self.service = DetectionService(self._config(), isolation_forest=self.isolation_forest)
        names = set(self.profile) | set(self.multipliers)
        self._adjusted = {name: StatisticalDetector(self._config(self._factor(name)))
                          for name in names if self._factor(name) != 1.0}

    def set_sensitivity(self, value: float) -> bool:
        value = max(0.0, min(1.0, float(value)))
        if value == self.sensitivity:
            return False
        self.sensitivity = value
        self._rebuild()
        return True

    def set_isolation_forest(self, detector: IsolationForestDetector | None) -> None:
        self.isolation_forest = detector
        self._rebuild()

    def set_profile(self, profile: Mapping[str, float]) -> None:
        self.profile = dict(profile)
        self._rebuild()

    def thresholds(self, detector: str) -> dict[str, float]:
        config = self._config(self._factor(detector))
        return {"z_score": config.z_score_threshold, "ratio": config.request_rate_ratio_threshold}

    def raise_threshold(self, detector: str, increase: float) -> float:
        """Applies the M3 suggestion rule to one numeric detector; returns the relative delta."""
        if detector not in NUMERIC_DETECTORS:
            return 0.0
        current = self.thresholds(detector)
        suggested = _map_numeric_threshold(current, increase)
        factor = suggested["z_score"] / current["z_score"]
        self.multipliers[detector] = self.multipliers.get(detector, 1.0) * factor
        self._rebuild()
        return round(factor - 1.0, 4)

    def detect(self, features: TrafficFeatures, endpoint_baseline: Mapping[str, Any],
               **kwargs: Any) -> list[DetectorResult]:
        results = self.service.detect(features, endpoint_baseline, **kwargs)
        if not self._adjusted:
            return results
        kwargs.pop("timings_ns", None)
        kwargs.pop("caller_baseline", None)
        replaced = {}
        for name, detector in self._adjusted.items():
            for result in detector.detect(features, endpoint_baseline, **kwargs):
                if result.detector == name:
                    replaced[name] = result
        return [replaced.get(r.detector, r) for r in results]


class LiveLearner:
    """One upstream's baseline, detectors and alerts, persisted through SqlLearningStorage."""

    def __init__(
        self,
        storage: SqlLearningStorage,
        settings: LiveSettings | None = None,
        *,
        baseline_config: BaselineConfig | None = None,
        detector_config: DetectorConfig | None = None,
        alert_config: AlertConfig | None = None,
        now: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
    ) -> None:
        self.storage = storage
        self.settings = settings or LiveSettings()
        self.upstream_id = self.settings.upstream_id
        self.baseline_config = baseline_config or BaselineConfig.from_env()
        self._now = now
        self.risk = SqlEndpointRiskProvider(storage, ttl=self.settings.risk_cache_seconds)
        self.alerts = AlertService(storage=storage, endpoint_risk_provider=self.risk,
                                   config=alert_config or AlertConfig())
        self.feedback = FeedbackService(storage=storage)
        self.feedback_increase = FeedbackAnalysisConfig().suggested_threshold_increase
        self.detection = TunedDetection(
            detector_config or DetectorConfig(min_samples=self.settings.detector_min_samples), None)
        self.disabled = False
        self.stats: dict[str, int] = {"processed": 0, "anomalous": 0, "alerts": 0, "suppressed_old": 0,
                                      "suppressed_warmup": 0}
        self._previous_endpoint: OrderedDict[str, str] = OrderedDict()
        tuning = storage.load_tuning(self.upstream_id)
        self.detection.multipliers = {k: float(v) for k, v in (tuning.get("multipliers") or {}).items()}
        self.detection.set_profile(dict(self.settings.threshold_profile))
        self._reset_handled_at: str | None = tuning.get("reset_handled_at")
        self._warmup_completed_at: str | None = tuning.get("warmup_completed_at")
        self._tuning_dirty = False
        self._new_models()

    # ---- models ------------------------------------------------------------------------

    def _new_models(self) -> None:
        self.baseline = BaselineLearner(self.baseline_config, storage=self.storage, upstream_id=self.upstream_id)
        self.isolation_forest = (
            IsolationForestDetector(IsolationForestConfig(min_samples=self.settings.if_min_samples),
                                    model_store=InMemoryModelStore())
            if self.settings.isolation_forest else None
        )
        self.detection.set_isolation_forest(self.isolation_forest)
        self._previous_endpoint.clear()

    def _tuning(self) -> dict[str, Any]:
        return {"multipliers": dict(self.detection.multipliers), "reset_handled_at": self._reset_handled_at,
                "warmup_completed_at": self._warmup_completed_at}

    # ---- per record ----------------------------------------------------------------------

    async def handle(self, envelope: FeatureEnvelope) -> None:
        """Consumer callback: raising leaves the entry un-ACKed for retry/dead-letter."""
        self.process(envelope.features)

    def process(self, features: TrafficFeatures) -> list[Alert]:
        endpoint = features.endpoint_key
        previous_endpoint = self._previous_endpoint.get(features.caller_id)
        endpoint_baseline = self.baseline.get_endpoint_baseline(endpoint)
        results = self.detection.detect(
            features,
            endpoint_baseline,
            all_baselines=self.baseline.get_all_baselines(),
            sequence_frequencies=self.baseline.get_sequence_frequencies(),
            previous_endpoint=previous_endpoint,
        )
        predicted_anomaly = any(r.detected for r in results)
        generated: list[Alert] = []
        if predicted_anomaly and not self.disabled:
            age = (self._now() - parse_ts(features.ts)).total_seconds()
            if age > self.settings.max_event_age_seconds:
                self.stats["suppressed_old"] += 1
            elif not self.settings.alert_during_warmup and self.learning_status()["mode"] != "active":
                self.stats["suppressed_warmup"] += 1
            else:
                generated = self.alerts.generate_alerts(results, features)
        update = self.baseline.update(features, trusted=not predicted_anomaly)
        if (self.isolation_forest is not None and update["accepted_for_baseline"]
                and update["state"] == ACTIVE):
            self.isolation_forest.observe(features, baseline_ready=True)
        self._previous_endpoint[features.caller_id] = endpoint
        self._previous_endpoint.move_to_end(features.caller_id)
        while len(self._previous_endpoint) > _PREVIOUS_ENDPOINT_CACHE:
            self._previous_endpoint.popitem(last=False)
        self.stats["processed"] += 1
        self.stats["anomalous"] += int(predicted_anomaly)
        self.stats["alerts"] += len(generated)
        return generated

    # ---- housekeeping (Admin control, feedback, progress) ------------------------------------

    def housekeeping(self) -> None:
        control = self.storage.read_learning_control()
        self.disabled = control.get("mode") == "disabled"
        if self.detection.set_sensitivity(control.get("sensitivity", 0.5)):
            log.info("sensitivity %.2f -> z threshold %.2f", self.detection.sensitivity,
                     self.detection.thresholds("latency")["z_score"])
        requested = control.get("reset_requested_at")
        if requested is not None:
            stamp = requested.astimezone(timezone.utc).isoformat()
            if self._reset_handled_at is None or stamp > self._reset_handled_at:
                self.reset(stamp)
        if self.risk.refresh_if_new_scan():
            log.info("new scan finished: endpoint risk reloaded")
        self.apply_feedback()
        self.write_state()
        if self._tuning_dirty:
            self._tuning_dirty = False
            self.storage.save_tuning(self.upstream_id, self._tuning())
        self.storage.flush_baselines()

    def reset(self, stamp: str | None = None) -> None:
        log.info("learning reset requested: dropping baselines and models")
        self.storage.clear_baseline(self.upstream_id)
        self._reset_handled_at = stamp or self._now().isoformat()
        self._warmup_completed_at = None
        self._new_models()
        self.storage.save_tuning(self.upstream_id, self._tuning())

    def apply_feedback(self) -> list[dict[str, Any]]:
        applied = []
        for row in self.storage.pending_feedback():
            detector = detector_for_label(row.get("feature"))
            delta: float | None = None
            feature = row.get("feature")
            if row["verdict"] == "false_positive":
                if detector is None:
                    detector = self._top_detector(row["alert_id"])
                    feature = DETECTOR_LABELS.get(detector, feature) if detector else feature
                delta = self.detection.raise_threshold(detector, self.feedback_increase) if detector else 0.0
            if row["verdict"] in ("false_positive", "true_positive") and self.storage.get_alert(row["alert_id"]):
                try:
                    self.feedback.submit_feedback(row["alert_id"], row["verdict"])
                except (KeyError, ValueError) as exc:
                    log.warning("feedback record skipped: %s", type(exc).__name__)
            self.storage.mark_feedback(row["id"], feature=feature, threshold_delta=delta)
            applied.append({"alert_id": row["alert_id"], "verdict": row["verdict"], "detector": detector,
                            "threshold_delta": delta})
            log.info("feedback %s on %s: detector %s, threshold delta %s", row["verdict"], row["alert_id"],
                     detector, delta)
        if applied:
            self.storage.save_tuning(self.upstream_id, self._tuning())
        return applied

    def _top_detector(self, alert_id: str) -> str | None:
        alert = self.storage.get_alert(alert_id)
        names = [n for n in (alert or {}).get("detector_names", []) if n in NUMERIC_DETECTORS]
        return names[0] if names else None

    def learning_status(self) -> dict[str, Any]:
        """Progress over the endpoints that have accepted normal observations (endpoints seen
        only in suspicious traffic never count). Warm-up is done the first time all of them are
        active, and stays done until a reset."""
        learned = [b for b in self.baseline.get_all_baselines().values() if b.get("first_seen")]
        if not learned:
            return {"mode": "warmup", "progress": 0.0, "started_at": None, "ends_at": None,
                    "endpoints_learned": 0, "shapes_learned": 0, "endpoints_seen": 0}
        progress = [self.baseline.get_endpoint_baseline(b["endpoint"])["warmup_progress"] for b in learned]
        active = [b for b in learned if b["state"] == ACTIVE]
        started = min(parse_ts(b["first_seen"]) for b in learned)
        if self._warmup_completed_at is None and len(active) == len(learned):
            self._warmup_completed_at = self._now().isoformat()
            self._tuning_dirty = True
            log.info("warm-up complete: %d endpoints active", len(active))
        done = self._warmup_completed_at is not None
        return {
            "mode": "active" if done else "warmup",
            "progress": 1.0 if done else sum(progress) / len(progress),
            "started_at": started,
            "ends_at": started + timedelta(seconds=self.baseline_config.warmup_period_seconds),
            "endpoints_learned": len(active),
            "shapes_learned": sum(len(b.get("learned_shape_hashes") or ()) for b in learned),
            "endpoints_seen": len(learned),
        }

    def write_state(self) -> dict[str, Any]:
        status = self.learning_status()
        self.storage.write_learning_state(
            mode=status["mode"], progress=status["progress"], started_at=status["started_at"],
            ends_at=status["ends_at"], endpoints_learned=status["endpoints_learned"],
            shapes_learned=status["shapes_learned"])
        return status

    def close(self) -> None:
        self.storage.flush_baselines(force=True)


async def wait_for_tables(storage: SqlLearningStorage, stop: asyncio.Event, every: float = 2.0) -> bool:
    while not stop.is_set():
        if storage.tables_ready():
            return True
        log.info("waiting for the Admin API to create the tables...")
        try:
            await asyncio.wait_for(stop.wait(), timeout=every)
        except asyncio.TimeoutError:
            pass
    return False


async def run_live(stop: asyncio.Event | None = None) -> None:
    """Entry point used by ``python -m apishield_learning``."""
    from .config import LearningConfig
    from .consumer import RedisStreamConsumer

    stop = stop or asyncio.Event()
    try:  # docker stop sends SIGTERM: finish the batch and flush the baseline
        import signal

        asyncio.get_running_loop().add_signal_handler(signal.SIGTERM, stop.set)
    except (NotImplementedError, AttributeError, RuntimeError):  # Windows
        pass
    config = LearningConfig.from_env()
    settings = LiveSettings.from_env()
    storage = SqlLearningStorage.from_url(settings.database_url, settings.upstream_id,
                                          flush_interval=settings.baseline_flush_seconds)
    if not await wait_for_tables(storage, stop):
        return
    learner = LiveLearner(storage, settings)
    log.info("live learner for %s: warm-up %.0fs / %d observations, isolation forest %s, db %s",
             settings.upstream_id, learner.baseline_config.warmup_period_seconds,
             learner.baseline_config.min_observations,
             f"on (min {settings.if_min_samples})" if settings.isolation_forest else "off",
             settings.database_url.split("@")[-1])
    consumer = RedisStreamConsumer.from_config(config)

    async def housekeeping_loop() -> None:
        last_log = 0.0
        while not stop.is_set():
            try:
                learner.housekeeping()
            except Exception as exc:  # the DB may be briefly unavailable; keep consuming
                log.warning("housekeeping failed: %s: %s", type(exc).__name__, exc)
            if time.monotonic() - last_log > 30:
                last_log = time.monotonic()
                status = learner.learning_status()
                log.info("status mode=%s progress=%.2f endpoints=%d/%d stats=%s if_trained=%s",
                         status["mode"], status["progress"], status["endpoints_learned"],
                         status["endpoints_seen"], learner.stats,
                         learner.isolation_forest.trained if learner.isolation_forest else None)
            try:
                await asyncio.wait_for(stop.wait(), timeout=settings.housekeeping_seconds)
            except asyncio.TimeoutError:
                pass

    task = asyncio.create_task(housekeeping_loop(), name="learner-housekeeping")
    try:
        await consumer.run(learner.handle, stop_event=stop)
    finally:
        stop.set()
        await task
        learner.close()
