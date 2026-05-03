#!/usr/bin/env python3
"""
DDoS Detection & Mitigation System — Entry Point
Orchestrates packet capture, detection, mitigation, alerting, and the API server.

Usage
-----
  # Full detection + mitigation + dashboard
  python main.py

  # Train models only (no server started)
  python main.py --train

  # Override capture interface at runtime
  python main.py --interface eth0

  # Detection-only (no firewall rules)
  python main.py --no-block

  # Verbose logging
  python main.py --debug
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import signal
import sys
import tempfile
import time
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

# ── Ensure project root is on sys.path before any local imports ──────────────
BASE_DIR = Path(__file__).resolve().parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

# ── Local imports ─────────────────────────────────────────────────────────────
from config.settings import (
    API_PORT,
    CAPTURE_INTERFACE,
    CONFIDENCE_THRESHOLD,
    DATA_DIR,
    DASHBOARD_PORT,
    DETECTION_THRESHOLD,
    LOGS_DIR,
    LOG_FORMAT,
    LOG_LEVEL,
    LOG_MAX_BYTES,
    LOG_BACKUP_COUNT,
    MODELS_DIR,
)
from src.alerting import alert_manager, on_detection_alert
from src.detector import DetectionEngine
from src.mitigation import MitigationEngine
from src.packet_capture import PacketCapture

logger = logging.getLogger(__name__)


def _resolve_writable_runtime_file(*candidates: Path) -> Path:
    for path in candidates:
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            with open(path, "a", encoding="utf-8"):
                pass
            return path
        except OSError:
            continue
    raise OSError(f"No writable runtime file path found in: {candidates!r}")

# ---------------------------------------------------------------------------
# Logging setup
# ---------------------------------------------------------------------------

def _configure_logging(debug: bool = False) -> None:
    """Configure root logger with rotating file + stderr handlers."""
    from logging.handlers import RotatingFileHandler

    level = logging.DEBUG if debug else getattr(logging, LOG_LEVEL.upper(), logging.INFO)

    root = logging.getLogger()
    root.setLevel(level)

    fmt = logging.Formatter(LOG_FORMAT, datefmt="%Y-%m-%dT%H:%M:%S")

    # Stderr handler
    ch = logging.StreamHandler(sys.stderr)
    ch.setLevel(level)
    ch.setFormatter(fmt)
    root.addHandler(ch)

    # Rotating file handler
    LOGS_DIR.mkdir(parents=True, exist_ok=True)
    log_candidates = [
        LOGS_DIR / "system.log",
        DATA_DIR / "system.log",
        Path(tempfile.gettempdir()) / "ddos-system.log",
    ]
    for log_path in log_candidates:
        try:
            log_path.parent.mkdir(parents=True, exist_ok=True)
            fh = RotatingFileHandler(
                log_path,
                maxBytes=LOG_MAX_BYTES,
                backupCount=LOG_BACKUP_COUNT,
                encoding="utf-8",
            )
            fh.setLevel(level)
            fh.setFormatter(fmt)
            root.addHandler(fh)
            root.debug("File logging enabled at %s", log_path)
            break
        except OSError:
            continue


# ---------------------------------------------------------------------------
# DDoSSystem
# ---------------------------------------------------------------------------

class DDoSSystem:
    """
    Top-level orchestrator.

    Lifecycle
    ---------
    DDoSSystem() → .start() → [running] → Ctrl+C / SIGTERM → .stop()

    All components are stored in ``self._comp`` and accessed via typed
    properties so the rest of the code never uses dict-key strings.
    """

    def __init__(
        self,
        interface: str = CAPTURE_INTERFACE,
        auto_block: bool = True,
        start_api: bool = True,
    ) -> None:
        self._interface   = interface
        self._auto_block  = auto_block
        self._start_api   = start_api
        self._running     = False
        self._stop_event  = threading.Event()

        # Component handles
        self._detector:   Optional[DetectionEngine]  = None
        self._mitigator:  Optional[MitigationEngine] = None
        self._alert_mgr:  Optional[Any]     = None
        self._capture:    Optional[PacketCapture]     = None

        # Ensure required directories exist
        for d in (LOGS_DIR, MODELS_DIR, DATA_DIR):
            d.mkdir(parents=True, exist_ok=True)

        _banner("DDoS Detection & Mitigation System")

    # ------------------------------------------------------------------
    # Typed component properties
    # ------------------------------------------------------------------

    @property
    def detector(self) -> Optional[DetectionEngine]:
        return self._detector

    @property
    def mitigator(self) -> Optional[MitigationEngine]:
        return self._mitigator

    # ------------------------------------------------------------------
    # Initialisation
    # ------------------------------------------------------------------

    def initialize(self) -> bool:
        """
        Instantiate and wire all components.

        Returns:
            ``True`` on success, ``False`` when a required component (model
            files) is missing and the operator should train first.
        """
        logger.info("Initialising components…")

        try:
            # 1. Detection engine
            logger.info("  [1/4] Loading detection model…")
            self._detector = DetectionEngine()
            logger.info("        model=%s  features=%d",
                        self._detector.model_name,
                        len(self._detector.feature_names or []))

            # 2. Mitigation engine
            logger.info("  [2/4] Initialising mitigation engine…")
            self._mitigator = MitigationEngine(auto_block=self._auto_block)
            logger.info("        firewall=%s  auto_block=%s",
                        self._mitigator._fw.name, self._auto_block)

            # 3. Alert manager (use the module singleton so API endpoints
            #     and packet-capture callbacks share the same in-memory state)
            logger.info("  [3/4] Starting alert manager…")
            self._alert_mgr = alert_manager
            logger.info("        email=%s  webhook=%s",
                        self._alert_mgr._email_enabled,
                        self._alert_mgr._webhook_enabled)

            # 4. Packet capture
            logger.info("  [4/4] Configuring packet capture…")
            self._capture = PacketCapture(
                interface=self._interface,
                callback=self._on_flow,
            )
            logger.info("        interface=%s", self._interface)

            logger.info("All components initialised.")
            return True

        except FileNotFoundError as exc:
            logger.error("Model artefacts not found: %s", exc)
            logger.error("Train models first:")
            logger.error("  python main.py --train")
            return False
        except Exception:
            logger.exception("Component initialisation failed.")
            return False

    # ------------------------------------------------------------------
    # Flow callback  (runs in the PacketCapture background thread)
    # ------------------------------------------------------------------

    def _on_flow(
        self,
        features: Dict[str, Any],
        flow_key: Optional[Tuple],
        is_anomaly: bool,
    ) -> None:
        """
        Called by :class:`~src.packet_capture.PacketCapture` for every
        completed flow.  Must be fast — heavy work is deferred to the
        detector / mitigator which are themselves thread-safe.
        """
        if self._detector is None:
            return

        src_ip = str(flow_key[0]) if flow_key else "0.0.0.0"
        dst_ip = str(flow_key[1]) if flow_key else "0.0.0.0"

        # Update detector packet count so stats are accurate
        self._detector.increment_packet_count(1)

        try:
            detection = self._detector.detect(features, src_ip=src_ip, dst_ip=dst_ip)
        except Exception:
            logger.exception("Detection error for flow %s → %s.", src_ip, dst_ip)
            return

        # ── Mitigation ─────────────────────────────────────────────────
        blocked = False
        if detection.get("is_attack") and self._mitigator is not None:
            conf = float(detection.get("confidence", 0))
            if conf >= CONFIDENCE_THRESHOLD:
                # Check rate limit first — blocks only genuinely volumetric flows
                if self._mitigator.check_rate_limit(src_ip):
                    blocked = self._mitigator.block_ip(
                        src_ip,
                        reason=f"Auto-block: {detection.get('attack_type', 'UNKNOWN')}  "
                               f"(conf={conf:.0%})",
                    )

        # ── Alerting ───────────────────────────────────────────────────
        alert = on_detection_alert(detection)

        # ── Update shared app_state counters (used by dashboard stats) ─
        try:
            import api_server
            with api_server.app_state._lock:
                api_server.app_state.total_flows += 1
                api_server.app_state.total_packets += 1
                if detection.get("is_attack"):
                    api_server.app_state.attacks_blocked += 1
                if alert is not None:
                    api_server.app_state.alerts_generated += 1
        except Exception:
            pass

        # ── Real-time dashboard push ───────────────────────────────────
        try:
            import api_server
            loop = api_server._main_loop
            if loop is not None and loop.is_running():
                import asyncio
                asyncio.run_coroutine_threadsafe(
                    api_server.ws_manager.send_typed("detection", detection),
                    loop,
                )
        except Exception:
            pass

        # ── Structured log ─────────────────────────────────────────────
        self._log_detection(detection)

    def _log_detection(self, detection: Dict[str, Any]) -> None:
        """Append detection event to the structured JSONL event log."""
        try:
            log_path = _resolve_writable_runtime_file(
                LOGS_DIR / "detections.jsonl",
                DATA_DIR / "detections.jsonl",
                Path(tempfile.gettempdir()) / "ddos-detections.jsonl",
            )
            line = json.dumps({
                "ts":  datetime.now(timezone.utc).isoformat(),
                **{k: v for k, v in detection.items() if k != "features"},
            })
            with open(log_path, "a", encoding="utf-8") as fh:
                fh.write(line + "\n")
        except OSError as exc:
            logger.error("Failed to write detection log: %s", exc)

    # ------------------------------------------------------------------
    # Start / stop
    # ------------------------------------------------------------------

    def start(self) -> None:
        """
        Initialise components, start all background services, and block
        the main thread until a stop signal is received.
        """
        if not self.initialize():
            sys.exit(1)

        _banner("STARTING SYSTEM")

        # ── Packet capture (background daemon thread inside PacketCapture) ──
        assert self._capture is not None
        self._capture.start()
        logger.info("Packet capture started on '%s'.", self._interface)

        # ── API / Dashboard (FastAPI + uvicorn in a daemon thread) ─────────
        if self._start_api:
            api_thread = threading.Thread(
                target=self._run_api,
                name="APIServerThread",
                daemon=True,
            )
            api_thread.start()

        self._running = True

        # ── Register OS signal handlers ────────────────────────────────────
        signal.signal(signal.SIGINT,  self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)

        logger.info("")
        if self._start_api:
            logger.info("  Dashboard  :  http://localhost:%d/dashboard", DASHBOARD_PORT)
            logger.info("  API docs   :  http://localhost:%d/docs",      API_PORT)
            logger.info("  WebSocket  :  ws://localhost:%d/ws/dashboard", API_PORT)
        else:
            logger.info("  API server : disabled (--detect-only)")
        logger.info("")
        logger.info("System running.  Press Ctrl+C to stop.")

        # ── Block main thread ──────────────────────────────────────────────
        try:
            self._stop_event.wait()
        except KeyboardInterrupt:
            pass   # SIGINT also sets the event via _signal_handler
        finally:
            self.stop()

    def stop(self) -> None:
        """Gracefully shut down every component in reverse order."""
        if not self._running:
            return
        self._running = False

        _banner("STOPPING SYSTEM")

        if self._capture:
            logger.info("Flushing and stopping packet capture…")
            self._capture.flush_all_flows()
            self._capture.stop()

        if self._alert_mgr:
            logger.info("Shutting down alert manager…")
            self._alert_mgr.shutdown(wait=True)

        logger.info("System stopped cleanly.")

    def _signal_handler(self, signum: int, _frame: Any) -> None:
        logger.info("Received signal %d — initiating shutdown.", signum)
        self._stop_event.set()

    # ------------------------------------------------------------------
    # API server
    # ------------------------------------------------------------------

    def _run_api(self) -> None:
        """
        Import and start the FastAPI / uvicorn server.

        Imported lazily so ``--train`` mode never loads the API module.
        """
        try:
            import api_server
            api_server.app_state.detector = self._detector
            api_server.app_state.mitigation = self._mitigator
            api_server.app_state.capture = self._capture
            api_server.app_state.alerts = self._alert_mgr
            run_server = api_server.run_server
            run_server()
        except Exception:
            logger.exception("API server crashed.")


# ---------------------------------------------------------------------------
# Training pipeline
# ---------------------------------------------------------------------------

def run_training(cv_folds: int = 0) -> None:
    """
    Execute the full data → model training pipeline and exit.

    Args:
        cv_folds: Stratified cross-validation folds (0 = skip).
    """
    import joblib

    _banner("TRAINING MODE")

    from src.data_pipeline import DataPipeline
    from src.model_trainer import ModelTrainer, train_models

    # ── Data preprocessing ─────────────────────────────────────────────
    logger.info("Step 1 / 2  — Data preprocessing…")
    pipeline = DataPipeline(scaler_type="standard")
    data = pipeline.run_pipeline(train=True)

    # Persist processed splits so model_trainer can load them independently
    out_path = MODELS_DIR / "processed_data.pkl"
    tmp_path = out_path.with_suffix(".tmp")
    joblib.dump(data, tmp_path)
    tmp_path.replace(out_path)
    logger.info("Processed data saved → %s", out_path)

    # ── Model training ─────────────────────────────────────────────────
    logger.info("Step 2 / 2  — Model training…")
    trainer = train_models(cv_folds=cv_folds)

    if trainer is None:
        logger.error("Training failed — processed data not found at '%s'.", out_path)
        sys.exit(1)

    _banner("TRAINING COMPLETE")
    logger.info("Best model  : %s", trainer.best_model_name)
    logger.info("Artefacts   : %s", MODELS_DIR)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="main.py",
        description="DDoS Detection & Mitigation System",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )

    # Mode
    mode = p.add_mutually_exclusive_group()
    mode.add_argument(
        "--train",
        action="store_true",
        help="Run the data pipeline and model training, then exit.",
    )
    mode.add_argument(
        "--detect-only",
        action="store_true",
        help="Run detection without starting the API / dashboard.",
    )

    # Capture
    p.add_argument("--interface",  default=CAPTURE_INTERFACE,
                   help="Network interface for packet capture.")

    # Mitigation
    p.add_argument("--no-block",   action="store_true",
                   help="Disable automatic IP blocking (detection-only mode).")

    # API
    p.add_argument("--api-port",   type=int, default=API_PORT,
                   help="Port for the FastAPI server.")

    # Training options
    p.add_argument("--cv-folds",   type=int, default=0,
                   help="Stratified CV folds during training (0 = skip).")

    # Logging
    p.add_argument("--debug",      action="store_true",
                   help="Enable DEBUG-level logging.")

    return p


# ---------------------------------------------------------------------------
# Utility
# ---------------------------------------------------------------------------

def _banner(title: str, width: int = 60) -> None:
    pad   = max(0, width - len(title) - 2)
    left  = pad // 2
    right = pad - left
    logger.info("%s %s %s", "=" * left, title, "=" * right)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    args = _build_parser().parse_args()

    _configure_logging(debug=args.debug)

    # ── Apply CLI overrides to settings ────────────────────────────────
    if args.interface != CAPTURE_INTERFACE:
        import config.settings as _s
        _s.CAPTURE_INTERFACE = args.interface
        logger.info("Capture interface overridden → %s", args.interface)

    if args.no_block:
        import config.settings as _s
        _s.AUTO_BLOCK_ENABLED = False
        logger.info("Auto-block disabled via CLI flag.")

    if args.api_port != API_PORT:
        import config.settings as _s
        _s.API_PORT = args.api_port
        logger.info("API port overridden → %d", args.api_port)

    # ── Dispatch ────────────────────────────────────────────────────────
    if args.train:
        run_training(cv_folds=args.cv_folds)
        return

    system = DDoSSystem(
        interface=args.interface,
        auto_block=not args.no_block,
        start_api=not args.detect_only,
    )
    system.start()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nInterrupted.")
    except Exception:
        logger.exception("Fatal error.")
        sys.exit(1)
