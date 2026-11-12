"""App factory. Every API route lives under /api; the built dashboard, when configured,
is served from /."""
from __future__ import annotations

import asyncio
import contextlib
import logging
from pathlib import Path

from alembic import command
from alembic.config import Config as AlembicConfig
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse

from . import demo_alerts, errors, rules_service, seed
from .config import Config
from .db import Base, make_engine, make_session_factory
from .gateway_client import GatewayClient
from .ingest import TrafficIngestor
from .models import ScanRow, SettingsRow
from .routes import admin, alerts, core, rules, scans, traffic
from .scans import ScanRunner

log = logging.getLogger("apishield.admin")
HERE = Path(__file__).resolve().parent
API_PREFIX = "/api"
DEMO_ALERT_SECONDS = 5.0


def migrate(database_url: str) -> None:
    alembic_cfg = AlembicConfig(str(HERE / "alembic.ini"))
    alembic_cfg.set_main_option("script_location", str(HERE / "migrations"))
    alembic_cfg.set_main_option("sqlalchemy.url", database_url)
    command.upgrade(alembic_cfg, "head")


def create_app(cfg: Config | None = None, *, gateway_transport=None, redis=None, scan_fn=None,
               run_background: bool = True) -> FastAPI:
    cfg = cfg or Config.from_env()
    engine = make_engine(cfg.database_url)
    if cfg.auto_migrate:
        migrate(cfg.database_url)
    else:
        Base.metadata.create_all(engine)
    session_factory = make_session_factory(engine)
    with session_factory() as session:
        seed.ensure_base_rows(session, cfg)
        if cfg.demo_seed:
            seed.seed_demo(session, cfg)
        for stale in session.query(ScanRow).filter(ScanRow.status.in_(("queued", "running"))):
            stale.status, stale.error = "failed", "Interrupted: the Admin API restarted during the scan."
        session.commit()

    gateway = GatewayClient(cfg.gateway_url, cfg.admin_token, transport=gateway_transport)
    ingestor = TrafficIngestor(cfg, session_factory, redis=redis)
    scan_runner = ScanRunner(cfg, session_factory, scan_fn=scan_fn)

    async def _demo_alert_loop() -> None:
        """ADMIN_DEMO_ALERTS=true: refresh demo-replay alerts every few seconds (stand-in for M3)."""
        while True:
            try:
                await asyncio.to_thread(demo_alerts.run_once, session_factory, ingestor, cfg.upstream_id)
            except Exception as exc:  # never let the demo helper take the API down
                log.warning("demo alert replay failed: %s", type(exc).__name__)
            await asyncio.sleep(DEMO_ALERT_SECONDS)

    def retention_days() -> int:
        with session_factory() as session:
            return session.get(SettingsRow, 1).retention_days

    @contextlib.asynccontextmanager
    async def lifespan(app: FastAPI):
        tasks = []
        if run_background:
            tasks.append(asyncio.create_task(ingestor.run(retention_days), name="admin-ingest"))
            tasks.append(asyncio.create_task(rules_service.sync_loop(app), name="admin-gateway-sync"))
            if cfg.demo_alerts:
                tasks.append(asyncio.create_task(_demo_alert_loop(), name="admin-demo-alerts"))
        try:
            yield
        finally:
            for task in tasks:
                task.cancel()
            for task in tasks:
                with contextlib.suppress(asyncio.CancelledError, Exception):
                    await task
            scan_runner.shutdown()
            await gateway.aclose()

    app = FastAPI(title="APIShield Admin API", lifespan=lifespan, docs_url=API_PREFIX + "/docs",
                  openapi_url=API_PREFIX + "/openapi.json", redoc_url=None)
    app.state.config = cfg
    app.state.engine = engine
    app.state.session_factory = session_factory
    app.state.gateway = gateway
    app.state.ingestor = ingestor
    app.state.scan_runner = scan_runner
    app.state.sse_heartbeat = 15.0
    app.state.gateway_rules_cache = []
    errors.install(app)
    if cfg.cors_origins:
        app.add_middleware(CORSMiddleware, allow_origins=cfg.cors_origins, allow_credentials=False,
                           allow_methods=["GET", "POST", "PATCH", "DELETE"],
                           allow_headers=["Authorization", "Content-Type"])

    for module in (core, traffic, rules, alerts, scans, admin):
        app.include_router(module.router, prefix=API_PREFIX)

    @app.get(API_PREFIX + "/health", include_in_schema=False)
    def health():
        return {"status": "ok", "redis": ingestor.redis_ok, "events_processed": ingestor.processed}

    if cfg.static_dir:
        _mount_dashboard(app, Path(cfg.static_dir))
    return app


def _mount_dashboard(app: FastAPI, root: Path) -> None:
    """Serve the built dashboard. Unknown paths fall back to index.html (client-side routing)."""
    root = root.resolve()
    index = root / "index.html"
    if not index.is_file():
        log.warning("ADMIN_STATIC_DIR %s has no index.html; the dashboard is not served", root)
        return

    @app.get("/{path:path}", include_in_schema=False)
    def dashboard(path: str):
        if path.startswith(API_PREFIX.strip("/") + "/"):
            raise errors.APIError(404, "not_found", "No such API route.")
        candidate = (root / path).resolve()
        if path and candidate.is_file() and root in candidate.parents:
            return FileResponse(candidate)
        return FileResponse(index)
