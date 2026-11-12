# APIShield Learning (M3)

The M3 package is the foundation for consuming gateway traffic, learning
baselines, detecting anomalies, and producing explainable alerts.

## Current status

- Configuration reads Redis, stream, M3 consumer-group, consumer-name, and
  shared pseudonymization settings from environment variables.
- `events.py` validates the gateway event contract without renaming or adding
  event fields.
- `consumer.py` provides a Redis Streams consumer-group interface. It uses a
  dedicated configured M3 group and provisions only that group. The team must
  ensure its configured name is distinct from M4's group. It reclaims stale
  pending messages with `XAUTOCLAIM`, falling back to `XPENDING`/`XCLAIM` when
  the Redis server does not support `XAUTOCLAIM`.
- `features.py` creates separate identifiers for internal baseline learning
  and alerts. Baseline caller/IP IDs are full-length, domain-separated HMACs
  derived from the shared salt. Alert caller IDs use the actual
  `admin_api.privacy.pseudonymize` function once on the original M1 caller.
  Alert IDs therefore match M4, including `key_` pass-through. Records include
  UTC time-of-day fields, endpoint/caller grouping keys, and request-rate
  inputs; raw caller/IP values and request IDs are omitted.
- `baselines.py` learns endpoint and pseudonymous caller/endpoint statistics
  with EWMA, bounded rolling metrics, warm-up state, shape allow-lists, and
  ordered endpoint transition counts. It writes JSON-safe snapshots through
  the storage interface.
- `storage.py` includes an in-memory adapter for deterministic development.
- `detectors/statistical.py` compares ready endpoint baselines with current
  rates, sizes, latency, error status, shape hashes, endpoint/method keys, rule
  hits/actions, and optionally supplied sequence context. Numeric detectors
  require an active baseline and enough metric samples; a new shape or
  enforcement event is a suspicious signal rather than an attack verdict.
- `detectors/isolation_forest.py` provides deterministic multivariate
  Isolation Forest training and scoring. It uses numeric status, log-scaled
  sizes/latency, and cyclical time features, and excludes blocked, throttled,
  and challenged events from normal training. Allow and log events remain
  eligible even with rule hits. Its 0–1 score is an empirical lower
  tail rank (higher means more unusual), not a probability. Models are saved
  through a `ModelStore`; the included in-memory store is development-only.
- `detectors/service.py` runs applicable statistical detectors and an
  optionally supplied Isolation Forest without Redis or dashboard coupling.
- `alerts.py` groups detected results into privacy-safe alerts, calculates
  priority, provides explanations, deduplicates active incidents, and supports
  retrieval, ranking, and status changes using `LearningStorage`.
- `feedback.py` stores append-only analyst labels and provides reviewable
  detector-level metrics and threshold recommendations. It does not change
  detector settings, baselines, or gateway rules.
- `replay.py` replays M1-shaped events or safe feature records through the
  feature, baseline, detector, and alert components, then emits a JSON
  evaluation and measured per-stage latency report.

The in-process M3 flow is:

```text
M1 Redis Stream -> TrafficEvent validation -> HMAC-safe TrafficFeatures
                 -> BaselineLearner -> DetectionService -> AlertService
                 -> LearningStorage
```

`FeedbackService` appends analyst labels and updates only the alert's
`feedback_status`. `ReplayEvaluator` uses the same feature, baseline, detector,
alert, and storage interfaces without connecting to Redis. M3 has no HTTP API
or dashboard integration; it reuses only the shared Admin API privacy function.

No payload values, credentials, authorization headers, or response bodies are
part of the M3 event or feature models. The gateway event itself includes a raw
IP and caller identifier, so treat parsed events as transient and do not persist
them directly. M3 uses the same `APISHIELD_PSEUDO_SALT` as M4. When it is not
set, both services use the Admin API's documented development-only fallback
`dev-only-pseudo-salt`; set a strong non-default value in `.env` outside local
development. M3 never hashes a shared alert caller ID a second time.

The consumer callback receives a `FeatureEnvelope` containing the Redis stream
entry ID and safe features. Use the entry ID as an idempotency key in the
downstream store. The consumer also keeps a bounded in-memory deduplication
cache; that cache alone does not guarantee exactly-once processing across
restarts.

## Configuration

| Variable | Default | Purpose |
|---|---|---|
| `APISHIELD_REDIS_URL` | `redis://127.0.0.1:6379/0` | Redis connection URL |
| `APISHIELD_EVENT_STREAM` | `apishield:traffic` | M1 traffic stream |
| `APISHIELD_LEARNING_CONSUMER_GROUP` | `learner` | Dedicated M3 group |
| `APISHIELD_LEARNING_CONSUMER_NAME` | Host name + process ID | M3 consumer identity |
| `APISHIELD_PSEUDO_SALT` | `dev-only-pseudo-salt` | Shared Admin API/M3 caller pseudonymization salt |
| `APISHIELD_LEARNING_BATCH_SIZE` | `100` | Maximum entries per read |
| `APISHIELD_LEARNING_BLOCK_MS` | `1000` | Redis blocking-read timeout |
| `APISHIELD_LEARNING_MIN_IDLE_MS` | `30000` | Minimum pending-message idle time before reclaim |
| `APISHIELD_LEARNING_MAX_DELIVERY_ATTEMPTS` | `5` | Failed processing attempts before dead-lettering |
| `APISHIELD_LEARNING_DEAD_LETTER_STREAM` | `apishield:m3:dead-letter` | M3-only bounded failure stream |
| `APISHIELD_LEARNING_DEAD_LETTER_MAXLEN` | `10000` | Approximate dead-letter stream cap |

The default M3 group is `learner`; M4's `admin-api` group is separate. The
consumer creates only its configured group with `MKSTREAM`, tolerating
`BUSYGROUP` if it already exists. It never creates, deletes, or modifies other
groups. Redis stream entries are expected to contain exactly one field,
`data`, with the compact JSON event.

Malformed events and failed callbacks remain pending and are retried. After the
configured delivery-attempt limit, the entry is written to the bounded
dead-letter stream with only its Redis entry ID, exception type, attempt count,
and failure timestamp; the original message is then acknowledged. The event
body is never logged or copied to the dead-letter stream. If writing the
dead-letter record fails, the original entry remains pending. Logs identify
entries by Redis stream ID and exception type only.

## Development and tests

From the repository root, install the M3 dependencies and run the test suite:

```powershell
python -m pip install -r learning\requirements.txt
python -m pytest -p no:cacheprovider learning/tests -q
```

The package requires Redis client support, scikit-learn for Isolation Forest,
and pytest for its tests. The same suite also works from `learning\` with
`python -m pytest -p no:cacheprovider tests -q`.

### Running the consumer

There is not yet a production M3 processing/storage service. The development
console consumer writes safe feature records to stdout; stdout must be secured
because pseudonymous IDs remain linkable. From the repository root in
PowerShell, set the shared salt to the same value used by Admin API, then run:

```powershell
$env:APISHIELD_REDIS_URL = "redis://127.0.0.1:6379/0"
$env:APISHIELD_PSEUDO_SALT = "<shared-secret-salt>"
$env:PYTHONPATH = "learning"
python -m apishield_learning
```

Press Ctrl+C for shutdown. For an application callback, construct
`RedisStreamConsumer.from_config(LearningConfig.from_env())` and pass
`consumer.run(callback, stop_event=...)`. The callback must complete its
idempotent processing successfully before the consumer acknowledges an event;
do not use a no-op callback. Use the Redis entry ID in `FeatureEnvelope` as the
downstream idempotency key.

### Docker Compose

The Compose `learning` service builds from [Dockerfile](./Dockerfile), installs
`learning/requirements.txt`, and copies the shared `admin_api.privacy` module
from the repository (not a duplicate). It connects to `redis://redis:6379/0`,
reads `apishield:traffic` in group `learner`, and receives
`APISHIELD_PSEUDO_SALT` from the same `.env` value as Admin API. From the
repository root:

```powershell
docker compose up --build redis learning
```

M3 currently runs the development consumer callback, which emits privacy-safe
features to container stdout. Learning storage remains in-memory; this service
does not persist baselines, alerts, or feedback to PostgreSQL, and no M3
PostgreSQL adapter is included.

The gateway supplies normalized `path_template` values, not concrete resource
IDs. Sequential resource-ID enumeration detection is therefore unsupported by
this event contract.

### Baseline learning

`BaselineLearner` accepts `TrafficFeatures` from `features.py`. Construct it
with `BaselineConfig.from_env()` to use these optional settings:

| Variable | Default | Purpose |
|---|---:|---|
| `APISHIELD_LEARNING_MIN_OBSERVATIONS` | `30` | Accepted observations required to activate an endpoint |
| `APISHIELD_LEARNING_WARMUP_SECONDS` | `3600` | Minimum time span before activation |
| `APISHIELD_LEARNING_EWMA_ALPHA` | `0.2` | EWMA smoothing factor |
| `APISHIELD_LEARNING_ROLLING_WINDOW_SIZE` | `1000` | Samples retained per rolling metric |
| `APISHIELD_LEARNING_MAX_SHAPES_PER_ENDPOINT` | `128` | Bound on learned shape hashes |
| `APISHIELD_LEARNING_RATE_WINDOW_SECONDS` | `60` | Request-rate bucket size |
| `APISHIELD_LEARNING_MIN_UPDATE_SAMPLES` | `5` | History required before numeric outlier gating |
| `APISHIELD_LEARNING_MAX_UPDATE_Z_SCORE` | `6.0` | Maximum deviation accepted for baseline adaptation |

Baseline state is `warmup` until both the time and accepted-sample requirements
are met. If the time period elapses before enough accepted samples arrive, the
state is `insufficient_data`; it continues learning but should not be treated
as high-confidence detector evidence. Blocked, throttled, challenged, and
rule-hit events count as observed but do not update statistics or shape
allow-lists. After activation, updates require `trusted=True` and a previously
learned shape. A novel post-warm-up shape is reported as an investigation
signal and is not learned automatically. Once enough history exists, numeric
observations beyond the configured Z-score bound are excluded during warm-up
and adaptation as well.

Endpoint-sequence counts are derived from events for the same pseudonymous
caller in strictly increasing event timestamp order. Out-of-order observations
do not create sequence transitions. No concrete resource identifier is
available to learn sequential-ID patterns.

### Anomaly detection

Construct a `StatisticalDetector` (or `DetectionService`) and pass a safe
`TrafficFeatures` record plus the endpoint baseline snapshot returned by
`BaselineLearner`. Numeric detectors use the configured Z-score threshold
(default 3) and request-rate EWMA ratio (default 3x); they require an active
baseline and at least five samples for that metric by default. A zero-variance
baseline treats a differing observation as an outlier. New shapes, unseen
endpoint/method keys, uncommon endpoint transitions (only when comparable
history is supplied), and enforcement/rule-hit events are surfaced as
suspicious signals, not proof of malicious activity.

`IsolationForestDetector` requires at least 100 valid normal samples by
default, uses `random_state=42`, and retrains after 100 additional observations
once eligible. Tune `IsolationForestConfig` for the deployment. Supply only
active-baseline features to `observe`; blocked, challenged, and throttled
records are excluded. Allow and log records remain eligible even when they
have rule hits; a log rule match is not itself treated as malicious. Invalid
actions or invalid rule-hit counts are rejected. `fit`, `observe`, `score`, and
`detect` are explicit operations, so callers control when training records are
accepted. The model store currently keeps trusted model objects in memory;
durable model persistence is an adapter responsibility and must not load
untrusted pickle files.

Detector scores are normalized to [0, 1], but are not attack probabilities.
Every result has `confirmed_attack=False`.

### Alert generation

Pass the detector results and the same safe `TrafficFeatures` record to
`AlertService.generate_alerts(...)`. A single observation with multiple
detected results creates one grouped caller/endpoint incident. Group keys are
SHA-256 hashes of the pseudonymous caller, endpoint/method key, and the general
`traffic_anomaly` type; raw caller and IP identifiers are rejected. Current
M3 HMAC pseudonyms and the Admin API's short `ip_`, `user_`, or `key_`
identifier formats are accepted, but M3 cannot generate the shared format
until the Admin API utility is available in this checkout.

An alert's anomaly score is the highest contributing detector score. When a
configured `EndpointRiskProvider` returns a normalized [0, 1] score, priority
is `min(1, anomaly_score * endpoint_risk_score * repeat_factor)`. The M2 risk
score remains separately visible. If risk is unavailable, the default formula
multiplier is `0.5`; `endpoint_risk_score` remains `None` so the fallback is
not represented as an M2 score. Provider values outside [0, 1] are rejected.
M2 adapters must normalize their actual contract before returning a value.

Repeat factor starts at 1.0, increases by 0.1 per subsequent observation, and
is capped at 2.0 by default. Deduplication updates a non-resolved alert for
the same pseudonymous caller and endpoint within the default 15-minute window.
Repeated feature timestamps are idempotent and do not increment the count.
Severity thresholds and all scoring/repeat settings are configurable through
`AlertConfig`. Scores are ranking indicators, not attack probabilities.

Use `get_alert`, `get_alerts`, `get_ranked_alerts`, `update_alert_status`, and
`get_alert_summary` on the service for in-process access. The existing
`InMemoryLearningStorage` provides development persistence only; no Admin API,
database, M2 transport, or M4 alert contract is implemented.

### Analyst feedback

Construct `FeedbackService(storage=...)` with the same `LearningStorage` used
by `AlertService`. `submit_feedback(alert_id, label, analyst_id=None,
comment=None)` appends every decision, including repeated labels, and links it
to the previous feedback record. `get_feedback` returns the latest decision;
`get_feedback_history` returns the ordered audit history. The alert's
`feedback_status` reflects the latest label without altering its detector
evidence or priority score.

Analyst IDs are optional and must be opaque identifiers, not names or email
addresses. Comments are optional and limited to 1000 characters; do not put
payloads, credentials, personal information, or other sensitive material in
them. Feedback labels are subjective analyst assessments, not verified attack
ground truth.

`get_feedback_summary` reports latest labels by alert severity.
`get_feedback_metrics` associates each latest alert label with all detectors
that contributed to that alert and reports counts and a false-positive rate.
This association is not causal detector attribution. High rates produce
review-only recommendations to consider increasing thresholds; there are no
automatic threshold changes, baseline/shape allow-list updates, caller blocks,
or gateway-rule changes.

### Replay evaluation and performance

The deterministic demo replay contains normal warm-up and post-warm-up traffic
followed by request-rate bursts, large request/response sizes, high latency,
4xx/5xx responses, a new payload shape, an unseen endpoint/method, and repeated
anomalous requests. Each record has an explicit `normal` or `abnormal` fixture
label. That ground truth is separate from detector predictions and any analyst
feedback. Synthetic replay metrics do not prove real-world detection accuracy.

From `learning\`, run the replay and print its JSON report:

```powershell
python -m apishield_learning.replay
```

Save a report, or compare statistical-only behavior:

```powershell
python -m apishield_learning.replay --output replay-report.json
python -m apishield_learning.replay --no-isolation-forest
```

The report includes confusion matrix, precision/recall/F1/false-positive rate,
scenario and detector metrics plus detection rates by each, grouped alert
repeat counts and severity counts, baseline warm-up
progress, and average/median/p95/maximum latency for feature extraction,
baseline update, statistical detection, optional Isolation Forest scoring,
alert generation, and overall processing. Measurements are for the current
single-process run and are not a production load test; the 20 ms p95 comparison
is calculated from measured results rather than assumed. The fixture's HMAC key
is a public demo-only value, not a deployment secret. Live Redis is not used.

Programmatic callers can compose `ReplayEvaluator(ReplayConfig(...))` with
`ReplayRecord(scenario=..., expected_label=..., event=...)` or the
`features=...` alternative. `calculate_metrics(expected, predicted)` provides
safe zero-denominator handling. Evaluator instances are one-shot so a second
run cannot silently inherit prior baselines or alerts.

#### Concise M3 demo procedure

1. From `learning\`, run `python -m apishield_learning.replay --output replay-report.json`.
2. Inspect `warmup` to confirm cold start, activation, and normal traffic after activation.
3. Inspect `per_scenario`, `per_detector`, and `alert_severity_counts` for the
   abnormal replay portion, including repeated incidents.
4. Review the measured `performance.stages.overall_processing.p95` for that run.
5. Treat all results as synthetic development evaluation, not proof of
   production accuracy or performance.

## Integration work still required

- Coordinate stream retention, consumer recovery, and event-gap handling with
  M1.
- Keep the M3 consumer group distinct from the M4 event-relay group.
- Confirm with M2 how endpoint risk is delivered and whether its path-only key
  is sufficient.
- Confirm M4 feedback request/response and alert/Learning-status details before
  wiring this in-process service to an API.
- Select durable storage with the platform owner; no database is selected here.
- Agree on pseudonymization-key provisioning and rotation. Rotating the key
  changes pseudonyms.
