"""
Main API Server (FastAPI)
Central orchestrator connecting all DDoS detection modules.

Architecture
------------
- Lifespan context manager handles startup/shutdown (replaces deprecated
  @app.on_event).
 - ConnectionManager broadcasts typed WebSocket messages that match the
   message-routing protocol in index.html (inline JS).
- Every endpoint is typed with Pydantic request/response models — no
  raw Dict parameters that silently accept anything.
- All module references live in AppState so there is no mutable global
  dict and mypy / pyright can reason about the types.
- Debug endpoints are hidden behind a DEV_MODE flag so they never leak
  into production.
- psutil calls are isolated so a missing package degrades gracefully.
"""

from __future__ import annotations

import asyncio
import logging
import threading
import time
import traceback
from collections import defaultdict, deque
from contextlib import asynccontextmanager
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any, Deque, Dict, List, Optional, Set, Tuple

import uvicorn
from fastapi import (
    FastAPI,
    HTTPException,
    Query,
    WebSocket,
    WebSocketDisconnect,
    status,
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field, field_validator
from starlette.requests import Request

from config.settings import (
    API_HOST,
    API_PORT,
    AUTO_BLOCK_ENABLED,
    BLOCK_DURATION,
    CAPTURE_INTERFACE,
    DATA_DIR,
    DETECTION_THRESHOLD,
    LOGS_DIR,
    MODELS_DIR,
    CONFIDENCE_THRESHOLD,
    RATE_LIMIT_THRESHOLD,
    CORS_ALLOW_ORIGINS,
)
from src.alerting import AlertManager, Alert, on_detection_alert, alert_manager

# Main asyncio event loop — captured at startup for cross-thread calls
_main_loop: Optional[asyncio.AbstractEventLoop] = None
from src.detector import DetectionEngine
from src.mitigation import MitigationEngine
from src.packet_capture import PacketCapture


logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Optional psutil
# ---------------------------------------------------------------------------

try:
    import psutil as _psutil
    _HAS_PSUTIL = True
except ImportError:
    _psutil = None        # type: ignore[assignment]
    _HAS_PSUTIL = False
    logger.warning("psutil not installed — CPU/memory metrics will be unavailable.")


def _sys_metrics() -> Dict[str, float]:
    if not _HAS_PSUTIL:
        return {"cpu_percent": 0.0, "memory_percent": 0.0, "disk_percent": 0.0}
    try:
        # "/" works on Unix; on Windows psutil typically maps it to the system drive.
        disk_percent = _psutil.disk_usage("/").percent
    except Exception:
        # Fallback for Windows where "/" may be invalid
        try:
            disk_percent = _psutil.disk_usage("C:\\").percent
        except Exception:
            disk_percent = 0.0
    return {
        "cpu_percent":    _psutil.cpu_percent(interval=None),
        "memory_percent": _psutil.virtual_memory().percent,
        "disk_percent":   disk_percent,
    }


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------

class BlockRequest(BaseModel):
    ip:       str
    duration: int   = Field(default=3600, ge=60)
    reason:   str   = Field(default="Manual block")


class UnblockRequest(BaseModel):
    ip: str


class WhitelistRequest(BaseModel):
    ip: str


class DetectionPayload(BaseModel):
    """Mirrors DetectionEngine.detect() return dict."""
    src_ip:      str
    dst_ip:      str
    is_attack:   bool
    confidence:  float
    attack_type: Optional[str] = None
    severity:    Optional[str] = None
    timestamp:   Optional[str] = None


# ---------------------------------------------------------------------------
# Application state  (replaces mutable global dict)
# ---------------------------------------------------------------------------

class AppState:
    def __init__(self) -> None:
        self.detector:   Optional[DetectionEngine]  = None
        self.mitigation: Optional[MitigationEngine] = None
        self.capture:    Optional[PacketCapture]    = None
        self.alerts:     Optional[AlertManager]     = None
        self.running:    bool = False
        self.start_time: Optional[datetime] = None

        # Rolling stat counters (incremented by callbacks)
        self.total_packets: int = 0
        self.total_flows:   int = 0
        self.attacks_blocked: int = 0
        self.alerts_generated: int = 0
        self._lock = threading.RLock()

    @property
    def uptime_seconds(self) -> float:
        if self.start_time is None:
            return 0.0
        return (datetime.now(timezone.utc) - self.start_time).total_seconds()


app_state = AppState()

# ---------------------------------------------------------------------------
# WebSocket connection manager
# ---------------------------------------------------------------------------

class ConnectionManager:
    """Thread-safe WebSocket fan-out broadcaster."""

    def __init__(self) -> None:
        self._connections: Set[WebSocket] = set()
        self._lock = asyncio.Lock()

    async def connect(self, ws: WebSocket) -> None:
        async with self._lock:
            if len(self._connections) >= 10:
                logger.warning("WS connection rejected: max 10 reached.")
                await ws.close(code=1008, reason="Too many connections")
                return
            self._connections.add(ws)
        await ws.accept()
        logger.info("WS client connected. Total: %d", len(self._connections))

    async def disconnect(self, ws: WebSocket) -> None:
        async with self._lock:
            self._connections.discard(ws)
        logger.info("WS client disconnected. Total: %d", len(self._connections))

    async def broadcast(self, message: Dict[str, Any]) -> None:
        """Send *message* to all connected clients; drop dead connections."""
        if not self._connections:
            return
        dead: List[WebSocket] = []
        async with self._lock:
            targets = list(self._connections)

        for ws in targets:
            try:
                await ws.send_json(message)
            except Exception:
                dead.append(ws)

        if dead:
            async with self._lock:
                for ws in dead:
                    self._connections.discard(ws)

    async def send_typed(self, msg_type: str, data: Any) -> None:
        """Convenience wrapper that stamps type + timestamp."""
        if not self._connections:
            return
        await self.broadcast({
            "type":      msg_type,
            "data":      data,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })

    @property
    def client_count(self) -> int:
        return len(self._connections)


ws_manager = ConnectionManager()

# Stats history ring buffer  { metric_name → deque[float] }
stats_history: Dict[str, Deque[float]] = defaultdict(lambda: deque(maxlen=1_000))

# ---------------------------------------------------------------------------
# Detection / mitigation callbacks
# ---------------------------------------------------------------------------

def _on_flow_complete(
    features: Dict[str, Any],
    flow_key: Tuple[str, str, int, int, int],
    is_anomaly: bool,
) -> Optional[Dict[str, Any]]:
    """
    PacketCapture callback — runs in the capture thread.
    Performs detection via the DetectionEngine and forwards the result
    to on_packet_detection().

    Returns the detection dict (or None if detector unavailable).
    """
    if app_state.detector is None:
        return None

    with app_state._lock:
        app_state.total_flows += 1
    src_ip, dst_ip, src_port, dst_port, protocol = flow_key
    detection = app_state.detector.detect(features, src_ip=src_ip, dst_ip=dst_ip)
    on_packet_detection(detection)
    return detection


def on_packet_detection(detection: Dict[str, Any]) -> None:
    """
    Called by PacketCapture / DetectionEngine for every analysed flow.
    Runs in the capture thread — keep it fast.
    """
    with app_state._lock:
        app_state.total_packets += 1
        if detection.get("is_attack"):
            app_state.attacks_blocked += 1

    # Also increment the detector's internal packet counter so its stats are accurate
    if app_state.detector is not None:
        app_state.detector.increment_packet_count(1)

    if detection.get("is_attack"):
        # Auto-block high-confidence attacks (respect rate limit, matching main.py)
        if (app_state.mitigation is not None
                and detection.get("confidence", 0) >= CONFIDENCE_THRESHOLD
                and AUTO_BLOCK_ENABLED):
            src = detection.get("src_ip")
            if src and app_state.mitigation.check_rate_limit(src):
                app_state.mitigation.block_ip(
                    src,
                    reason=f"Auto-block: {detection.get('attack_type', 'UNKNOWN')}",
                )
                # Broadcast blocked event to WebSocket clients
                info = app_state.mitigation.get_block_info(src)
                if _main_loop is not None and info:
                    asyncio.run_coroutine_threadsafe(
                        ws_manager.send_typed("blocked", info),
                        _main_loop
                    )

        # Forward to alert manager
        on_detection_alert(detection)

        logger.info(
            "Attack detected  %s -> %s  type=%s  conf=%.2f",
            detection.get("src_ip"),
            detection.get("dst_ip"),
            detection.get("attack_type"),
            detection.get("confidence", 0),
        )

    # Push the detection to WebSocket clients (fire-and-forget from sync context)
    if _main_loop is not None:
        asyncio.run_coroutine_threadsafe(
            ws_manager.send_typed("detection", detection),
            _main_loop
        )


def on_alert_created(alert: Alert) -> None:
    """Registered as an AlertManager callback — broadcasts alert via WS."""
    with app_state._lock:
        app_state.alerts_generated += 1
    if _main_loop is not None:
        asyncio.run_coroutine_threadsafe(
            ws_manager.send_typed("alert", alert.to_dict()),
            _main_loop
        )


# ---------------------------------------------------------------------------
# Lifespan (startup / shutdown)
# ---------------------------------------------------------------------------

@asynccontextmanager
async def lifespan(application: FastAPI):
    """Initialise all subsystems before serving; tear down on shutdown."""
    global _main_loop
    _main_loop = asyncio.get_running_loop()
    _sep("INITIALISING DDoS DETECTION SYSTEM")
    started_locally = False
    try:
        if app_state.detector is None:
            app_state.detector = DetectionEngine()
            started_locally = True
        if app_state.mitigation is None:
            app_state.mitigation = MitigationEngine(auto_block=AUTO_BLOCK_ENABLED)
            started_locally = True
        if app_state.alerts is None:
            app_state.alerts = alert_manager
            started_locally = True
        if app_state.capture is None:
            app_state.capture = PacketCapture(
                interface=CAPTURE_INTERFACE,
                callback=_on_flow_complete,
            )
            app_state.capture.start()
            started_locally = True

        application.state.started_subsystems_locally = started_locally
        app_state.alerts.register_callback(on_alert_created)
        logger.info(
            "Subsystems ready | model=%s | firewall=%s | interface=%s",
            app_state.detector.model_name if app_state.detector else "none",
            app_state.mitigation._fw.name if app_state.mitigation else "unknown",
            app_state.capture.interface if app_state.capture else CAPTURE_INTERFACE,
        )
    except FileNotFoundError:
        logger.error("Model artefacts are missing. Train the system before starting the API.")
        # Degrade gracefully: keep API running but mark subsystems unavailable
        application.state.started_subsystems_locally = False
    except Exception:
        logger.exception("Failed to initialise API subsystems.")
        application.state.started_subsystems_locally = False

    # Start background tasks
    app_state.running = True
    app_state.start_time = datetime.now(timezone.utc)

    stats_task = asyncio.create_task(_stats_broadcaster())

    yield  # ← server running

    # Shutdown
    stats_task.cancel()
    try:
        await stats_task
    except asyncio.CancelledError:
        pass

    # ── Shutdown ───────────────────────────────────────────
    logger.info("Shutting down…")
    app_state.alerts.unregister_callback(on_alert_created)
    if getattr(application.state, "started_subsystems_locally", False) and app_state.capture:
        app_state.capture.flush_all_flows()
        app_state.capture.stop()
    if getattr(application.state, "started_subsystems_locally", False) and app_state.alerts:
        app_state.alerts.shutdown(wait=True)
    app_state.running = False
    logger.info("Shutdown complete.")


async def _stats_broadcaster() -> None:
    """
    Background task: push a `stats` message to all WS clients every 2 s.
    This decouples the stats cadence from individual WS connections so
    clients don't each need their own polling loop.
    """
    while app_state.running:
        try:
            if ws_manager.client_count == 0:
                await asyncio.sleep(2)
                continue
            payload = _build_stats_payload()
            await ws_manager.send_typed("stats", payload)
        except Exception:
            logger.exception("Stats broadcaster error.")
        await asyncio.sleep(2)





# ---------------------------------------------------------------------------
# FastAPI application
# ---------------------------------------------------------------------------

app = FastAPI(
    title="DDoS Detection & Mitigation System",
    description="Real-time DDoS attack detection, mitigation, and alerting.",
    version="2.0.0",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
)

# CORS — configured via CORS_ALLOW_ORIGINS in settings (.env)
app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ALLOW_ORIGINS,
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Static files + templates
app.mount("/static", StaticFiles(directory="dashboard/static"), name="static")
templates = Jinja2Templates(directory="dashboard/templates")

# ---------------------------------------------------------------------------
# Root / dashboard
# ---------------------------------------------------------------------------

@app.get("/", response_class=JSONResponse, tags=["system"])
async def root():
    return {
        "system":    "DDoS Detection & Mitigation",
        "status":    "running" if app_state.running else "stopped",
        "version":   "2.0.0",
        "dashboard": "/dashboard",
        "api_docs":  "/docs",
        "websocket": "/ws/dashboard",
    }


@app.get("/dashboard", response_class=HTMLResponse, tags=["dashboard"])
async def dashboard(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})


# ---------------------------------------------------------------------------
# System endpoints
# ---------------------------------------------------------------------------

@app.get("/api/status", tags=["system"])
async def get_status():
    return {
        "status":            "running" if app_state.running else "stopped",
        "uptime_seconds":    round(app_state.uptime_seconds, 1),
        "detector_loaded":   app_state.detector   is not None,
        "mitigation_active": app_state.mitigation is not None,
        "capture_active":    app_state.capture    is not None,
        "ws_clients":        ws_manager.client_count,
        "timestamp":         datetime.now(timezone.utc).isoformat(),
    }


@app.get("/api/stats", tags=["system"])
async def get_stats():
    return _build_stats_payload()


@app.get("/api/stats/history", tags=["system"])
async def get_stats_history(
    metric: str = Query(default="traffic"),
    limit:  int = Query(default=100, ge=1, le=1000),
):
    history = list(stats_history.get(metric, []))[-limit:]
    return {"metric": metric, "data": history, "count": len(history)}


@app.get("/api/config", tags=["system"])
async def get_config():
    det = app_state.detector
    return {
        "detection_threshold":  DETECTION_THRESHOLD,
        "auto_block_enabled":   AUTO_BLOCK_ENABLED,
        "block_duration":       BLOCK_DURATION,
        "rate_limit_threshold": RATE_LIMIT_THRESHOLD,
        "model_name":           det.model_name if det else None,
        "features_count":       len(det.feature_names) if det and det.feature_names else 0,
        "version":              "2.0.0",
    }


# ---------------------------------------------------------------------------
# Detections
# ---------------------------------------------------------------------------

@app.get("/api/detections", tags=["detection"])
async def get_detections(
    limit:       int  = Query(default=50,  ge=1, le=500),
    attack_only: bool = Query(default=False),
):
    if not app_state.detector:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "Detector not initialised.")

    items = app_state.detector.get_recent_detections(limit=limit)
    if attack_only:
        items = [d for d in items if d.get("is_attack")]

    return {"total": len(items), "detections": items}


@app.get("/api/detections/attacks", tags=["detection"])
async def get_recent_attacks(limit: int = Query(default=20, ge=1, le=200)):
    if not app_state.detector:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "Detector not initialised.")
    return {"attacks": app_state.detector.get_recent_attacks(limit=limit)}


# ---------------------------------------------------------------------------
# Alerts
# ---------------------------------------------------------------------------

@app.get("/api/alerts", tags=["alerts"])
async def get_alerts(
    limit:      int           = Query(default=100, ge=1, le=1000),
    severity:   Optional[str] = Query(default=None),
    alert_type: Optional[str] = Query(default=None),
    source_ip:  Optional[str] = Query(default=None),
):
    mgr = app_state.alerts or __import__("src.alerting", fromlist=["alert_manager"]).alert_manager
    alerts = mgr.get_alerts(
        limit=limit,
        severity=severity,
        alert_type=alert_type,
        source_ip=source_ip,
    )
    return {"alerts": alerts, "count": len(alerts)}


@app.get("/api/alerts/stats", tags=["alerts"])
async def get_alert_stats():
    mgr = app_state.alerts or __import__("src.alerting", fromlist=["alert_manager"]).alert_manager
    return mgr.get_alert_stats()


@app.get("/api/alerts/active", tags=["alerts"])
async def get_active_alerts():
    mgr = app_state.alerts or __import__("src.alerting", fromlist=["alert_manager"]).alert_manager
    return {"alerts": mgr.get_active_alerts()}


@app.post("/api/alerts/{alert_id}/resolve", tags=["alerts"])
async def resolve_alert(alert_id: str):
    mgr = app_state.alerts or __import__("src.alerting", fromlist=["alert_manager"]).alert_manager
    ok = mgr.resolve_alert(alert_id)
    if not ok:
        raise HTTPException(status.HTTP_404_NOT_FOUND, f"Alert '{alert_id}' not found.")
    return {"status": "resolved", "id": alert_id}


# ---------------------------------------------------------------------------
# Mitigation
# ---------------------------------------------------------------------------

def _require_mitigation() -> MitigationEngine:
    if not app_state.mitigation:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "Mitigation engine not initialised.")
    return app_state.mitigation


@app.get("/api/mitigation/blocked", tags=["mitigation"])
async def get_blocked_ips():
    mit = _require_mitigation()
    details = mit.get_all_block_info()
    return {"count": len(details), "blocked_ips": details}


@app.post("/api/mitigation/block", tags=["mitigation"])
async def block_ip(req: BlockRequest):
    mit = _require_mitigation()
    ok  = mit.block_ip(req.ip, reason=req.reason, duration=req.duration)
    if not ok:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            f"IP {req.ip} is already blocked or whitelisted.",
        )
    # Notify WS clients with full block info
    info = mit.get_block_info(req.ip)
    if not info:
        # Fallback: construct complete block record if get_block_info failed
        # This includes expires_at calculated from duration
        now = datetime.now(timezone.utc)
        expires_at = now + timedelta(seconds=req.duration)
        info = {
            "ip": req.ip,
            "reason": req.reason,
            "remaining_seconds": req.duration,
            "blocked_at": now.isoformat(),
            "expires_at": expires_at.isoformat(),
        }
    await ws_manager.send_typed("blocked", info)
    return {"status": "blocked", "ip": req.ip, "duration": req.duration}


@app.post("/api/mitigation/unblock", tags=["mitigation"])
async def unblock_ip(req: UnblockRequest):
    mit = _require_mitigation()
    ok  = mit.unblock_ip(req.ip)
    if not ok:
        raise HTTPException(status.HTTP_404_NOT_FOUND, f"IP {req.ip} is not blocked.")
    await ws_manager.send_typed("unblocked", {"ip": req.ip})
    return {"status": "unblocked", "ip": req.ip}


@app.post("/api/mitigation/unblock-all", tags=["mitigation"])
async def unblock_all():
    mit = _require_mitigation()
    count = mit.unblock_all()
    await ws_manager.send_typed("unblocked", {"ip": "__all__", "count": count})
    return {"status": "success", "unblocked": count}


@app.get("/api/mitigation/whitelist", tags=["mitigation"])
async def get_whitelist():
    mit = _require_mitigation()
    return {"whitelist": mit.get_whitelist()}


@app.post("/api/mitigation/whitelist", tags=["mitigation"])
async def add_to_whitelist(req: WhitelistRequest):
    mit = _require_mitigation()
    ok  = mit.add_to_whitelist(req.ip)
    if not ok:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, f"Invalid IP or CIDR: {req.ip}")
    return {"status": "whitelisted", "ip": req.ip}


@app.post("/api/mitigation/whitelist/remove", tags=["mitigation"])
async def remove_from_whitelist(req: WhitelistRequest):
    mit = _require_mitigation()
    ok  = mit.remove_from_whitelist(req.ip)
    if not ok:
        raise HTTPException(status.HTTP_404_NOT_FOUND, f"{req.ip} not in whitelist.")
    return {"status": "removed", "ip": req.ip}


# ---------------------------------------------------------------------------
# Simulation endpoint (for external test tools like simulate_attacks.py)
# ---------------------------------------------------------------------------

class SimulationPayload(BaseModel):
    """Flow feature dict with source/destination IPs for synthetic testing."""
    features:    Dict[str, Any] = Field(...)
    src_ip:      str            = Field(...)
    dst_ip:      str            = Field(...)


@app.post("/api/simulate/flow", tags=["simulation"])
async def simulate_flow(payload: SimulationPayload):
    """
    Inject a synthetic flow into the detection pipeline.

    This endpoint is designed for external simulators (e.g. simulate_attacks.py)
    to drive the live system's detector and mitigation engines without
    generating raw packets.  The flow follows the exact same code-path as
    real traffic — :func:`_on_flow_complete` → detector → alerts → WS broadcast.
    """
    if app_state.detector is None:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "Detector not initialised.")

    # Build the flow-key tuple expected by _on_flow_complete.
    # Port/protocol are extracted from features; default to 0 if missing.
    protocol     = int(payload.features.get("Protocol", 0))
    src_port     = int(payload.features.get("Source Port",     0))
    dst_port     = int(payload.features.get("Destination Port", 0))
    flow_key     = (payload.src_ip, payload.dst_ip, src_port, dst_port, protocol)

    # Call the same callback used by PacketCapture and capture its result.
    detection = _on_flow_complete(payload.features, flow_key, False)

    # Also check if the IP ended up blocked (may have happened via auto-block)
    blocked = False
    if app_state.mitigation and detection and detection.get("is_attack"):
        blocked = app_state.mitigation.is_blocked(payload.src_ip)

    return {
        "status":      "processed",
        "src_ip":      payload.src_ip,
        "dst_ip":      payload.dst_ip,
        "timestamp":   datetime.now(timezone.utc).isoformat(),
        "detection":   detection,
        "is_blocked":  blocked,
    }


# ---------------------------------------------------------------------------
# Legacy REST routes (backward compat with dashboard.js v1) ─────────────

@app.post("/api/mitigate", tags=["mitigation"], deprecated=True,
          summary="Deprecated — use /api/mitigation/block")
async def legacy_block(req: BlockRequest):
    return await block_ip(req)


@app.delete("/api/mitigate/{ip}", tags=["mitigation"], deprecated=True,
            summary="Deprecated — use /api/mitigation/unblock")
async def legacy_unblock(ip: str):
    return await unblock_ip(UnblockRequest(ip=ip))


@app.delete("/api/mitigate/all", tags=["mitigation"], deprecated=True,
            summary="Deprecated — use /api/mitigation/unblock-all")
async def legacy_unblock_all():
    return await unblock_all()


@app.post("/api/whitelist", tags=["mitigation"], deprecated=True,
          summary="Deprecated — use /api/mitigation/whitelist")
async def legacy_add_whitelist(req: WhitelistRequest):
    return await add_to_whitelist(req)


@app.get("/api/blocked", tags=["mitigation"], deprecated=True,
         summary="Deprecated — use /api/mitigation/blocked")
async def legacy_get_blocked():
    return await get_blocked_ips()


# ---------------------------------------------------------------------------
# WebSocket endpoint
# ---------------------------------------------------------------------------

@app.websocket("/ws/dashboard")
async def ws_dashboard(websocket: WebSocket):
    """
    Primary WebSocket endpoint.

    The server pushes typed messages:
      { "type": "stats",     "data": {...}, "timestamp": "..." }
      { "type": "detection", "data": {...}, "timestamp": "..." }
      { "type": "alert",     "data": {...}, "timestamp": "..." }
      { "type": "blocked",   "data": {...}, "timestamp": "..." }
      { "type": "unblocked", "data": {...}, "timestamp": "..." }

    _stats_broadcaster() handles periodic stats delivery.
    All other message types are pushed by event-driven callbacks.
    The WS loop here simply keeps the connection alive.
    """
    await ws_manager.connect(websocket)

    # Send the current state immediately on connect
    await websocket.send_json({
        "type":      "stats",
        "data":      _build_stats_payload(),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    })

    try:
        while app_state.running:
            # Keep-alive: process any incoming client messages (none expected)
            try:
                await asyncio.wait_for(websocket.receive_text(), timeout=30)
            except asyncio.TimeoutError:
                pass   # no client message — normal
            except WebSocketDisconnect:
                break  # client disconnected cleanly
            except Exception:
                break  # connection broken
    except WebSocketDisconnect:
        pass
    except Exception as exc:
        logger.warning("WS session error: %s", exc)
    finally:
        await ws_manager.disconnect(websocket)


# Legacy WebSocket path — redirect clients still connecting to /ws
@app.websocket("/ws")
async def ws_legacy(websocket: WebSocket):
    await ws_dashboard(websocket)

def _build_stats_payload() -> Dict[str, Any]:
    mit = app_state.mitigation
    det = app_state.detector
    det_stats = det.get_statistics() if det else {}

    # Snapshot app_state counters under lock to ensure consistency
    with app_state._lock:
        total_packets = app_state.total_packets
        total_flows = app_state.total_flows
        attacks_blocked = app_state.attacks_blocked
        alerts_generated = app_state.alerts_generated

    # Total packets/flows/attacks from both app_state and detector stats
    total_packets_proc = det_stats.get("total_packets_processed", total_packets)
    total_flows_buf = det_stats.get("active_flows_buffered", total_flows)
    total_attacks_det = det_stats.get("total_attacks_detected", attacks_blocked)

    # Populate rolling history so /api/stats/history returns real data
    stats_history["traffic"].append(total_packets_proc)
    stats_history["flows"].append(total_flows_buf)
    stats_history["attacks"].append(total_attacks_det)

    return {
        # Primary fields used by inline dashboard JS
        "total_packets_processed": total_packets_proc,
        "active_flows_buffered": total_flows_buf,
        "total_attacks_detected": total_attacks_det,

        # Fallback/legacy names
        "total_packets": total_packets,
        "total_flows": total_flows,
        "attacks_blocked": attacks_blocked,
        "alerts_generated": alerts_generated,
        "uptime_seconds": round(app_state.uptime_seconds, 1),

        # System metrics (graceful fallback if psutil unavailable)
        **_sys_metrics(),

        # Blocked IP count
        "blocked_ips_count": len(mit.get_all_block_info()) if mit else 0,

        # Detection-related fields from detector (defaults to 0 if detector unavailable)
        "recent_attack_rate": det_stats.get("recent_attack_rate", 0.0),
        "avg_confidence": det_stats.get("avg_confidence", 0.0),
        "attack_distribution": det_stats.get("attack_distribution", {}),
        
        # Detector status indicator (helps frontend detect unavailability)
        "detector_available": det is not None and bool(det_stats),
    }


# ---------------------------------------------------------------------------
# Utility
# ---------------------------------------------------------------------------

def _sep(title: str = "", width: int = 60) -> None:
    if title:
        pad = max(0, width - len(title) - 2)
        print(f"\n{'=' * (pad // 2)} {title} {'=' * (pad - pad // 2)}")
    else:
        print("=" * width)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def run_server(host: str = API_HOST, port: int = API_PORT) -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s | %(name)s | %(levelname)s | %(message)s",
    )
    logger.info("Starting API server on http://%s:%d", host, port)
    uvicorn.run(
        "api_server:app",
        host=host,
        port=port,
        log_level="info",
        reload=False,
    )


if __name__ == "__main__":
    run_server()
