#!/usr/bin/env python3
"""
DDoS Detection & Mitigation System — Quick-Start Launcher

This script is the single command needed to get the system running:

  python run.py              # auto-train if needed, then start
  python run.py --train      # force retrain, then start
  python run.py --check      # dependency + model check only, no start
  python run.py --no-block   # detection mode, no firewall rules
  python run.py --interface eth0  # override capture interface

All arguments after '--' are forwarded verbatim to main.py.
"""

from __future__ import annotations

import argparse
import importlib
import subprocess
import sys
from pathlib import Path
from typing import List, Optional, Tuple

# ── Project root ─────────────────────────────────────────────────────────────
BASE_DIR = Path(__file__).resolve().parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

# ── Artefact paths ────────────────────────────────────────────────────────────
MODELS_DIR = BASE_DIR / "models"
REQUIRED_ARTEFACTS = [
    "random_forest.pkl",
    "scaler.pkl",
    "feature_names.pkl",
]

# ── Minimum required packages (import name → pip package name) ────────────────
REQUIRED_PACKAGES: List[Tuple[str, str]] = [
    ("fastapi",    "fastapi"),
    ("uvicorn",    "uvicorn[standard]"),
    ("sklearn",    "scikit-learn"),
    ("numpy",      "numpy"),
    ("pandas",     "pandas"),
    ("scapy",      "scapy"),
    ("joblib",     "joblib"),
    ("dotenv",     "python-dotenv"),
    ("pydantic",   "pydantic"),
    ("requests",   "requests"),
]

OPTIONAL_PACKAGES: List[Tuple[str, str]] = [
    ("xgboost",   "xgboost"),
    ("psutil",    "psutil"),
]

# ── ANSI colours (disabled on Windows unless ANSICON / WT is present) ─────────
_USE_COLOUR = sys.stdout.isatty() and sys.platform != "win32"

def _c(text: str, code: str) -> str:
    return f"\033[{code}m{text}\033[0m" if _USE_COLOUR else text

def ok(msg: str)   -> str: return _c(f"[  OK  ] {msg}", "32")
def info(msg: str) -> str: return _c(f"[ INFO ] {msg}", "36")
def warn(msg: str) -> str: return _c(f"[ WARN ] {msg}", "33")
def err(msg: str)  -> str: return _c(f"[ ERR  ] {msg}", "31")
def hdr(msg: str)  -> str: return _c(msg, "1;34")


# ---------------------------------------------------------------------------
# Dependency checks
# ---------------------------------------------------------------------------

def check_python_version() -> bool:
    """Require Python 3.9+."""
    major, minor = sys.version_info[:2]
    if (major, minor) < (3, 9):
        print(err(f"Python 3.9+ required - found {major}.{minor}."))
        return False
    print(ok(f"Python {major}.{minor}.{sys.version_info[2]}"))
    return True


def check_packages() -> Tuple[bool, List[str]]:
    """
    Verify all required packages are importable.

    Returns:
        ``(all_ok, missing_pip_names)``
    """
    missing: List[str] = []

    print(info("Checking required packages…"))
    for import_name, pip_name in REQUIRED_PACKAGES:
        try:
            importlib.import_module(import_name)
            print(f"    {ok(pip_name)}")
        except ImportError:
            print(f"    {err(pip_name + '  ← MISSING')}")
            missing.append(pip_name)

    print(info("Checking optional packages…"))
    for import_name, pip_name in OPTIONAL_PACKAGES:
        try:
            importlib.import_module(import_name)
            print(f"    {ok(pip_name)}")
        except ImportError:
            print(f"    {warn(pip_name + '  ← not installed (optional)')}")

    return len(missing) == 0, missing


def offer_install(missing: List[str]) -> bool:
    """
    Offer to install missing packages.  Returns True when the user
    accepts and installation succeeds.
    """
    print()
    print(warn(f"{len(missing)} required package(s) missing: {', '.join(missing)}"))
    choice = _prompt("Install them now with pip?", default="Y")
    if choice.lower() != "y":
        return False

    cmd = [sys.executable, "-m", "pip", "install"]
    if sys.platform.startswith("linux") and sys.prefix == getattr(sys, "base_prefix", sys.prefix):
        cmd.append("--break-system-packages")
    cmd += missing
    print(info(f"Running: {' '.join(cmd)}"))
    result = subprocess.run(cmd)
    if result.returncode != 0:
        print(err("pip install failed. Run manually:"))
        print(f"  pip install {' '.join(missing)}")
        return False

    print(ok("Packages installed."))
    return True


# ---------------------------------------------------------------------------
# Model artefact checks
# ---------------------------------------------------------------------------

def models_present() -> bool:
    """Return True when all required model artefacts exist."""
    return all((MODELS_DIR / f).exists() for f in REQUIRED_ARTEFACTS)


def check_models() -> bool:
    """Print model status and return True when artefacts are present."""
    print(info("Checking model artefacts…"))
    all_ok = True
    for fname in REQUIRED_ARTEFACTS:
        path = MODELS_DIR / fname
        if path.exists():
            size = path.stat().st_size / 1024
            print(f"    {ok(fname)}  ({size:.0f} KB)")
        else:
            print(f"    {err(fname + '  ← NOT FOUND')}")
            all_ok = False
    return all_ok


# ---------------------------------------------------------------------------
# Training pipeline
# ---------------------------------------------------------------------------

def run_training(force: bool = False) -> bool:
    """
    Execute data_pipeline.py then model_trainer.py as subprocesses.

    Running as subprocesses (not imports) ensures each step gets a clean
    interpreter state with no leftover module-level state from a prior run.

    Args:
        force: When True, skip the user prompt and retrain unconditionally.

    Returns:
        True when training succeeded.
    """
    if not force and models_present():
        choice = _prompt("Models already exist. Retrain from scratch?", default="N")
        if choice.lower() != "y":
            print(info("Skipping retraining - using existing models."))
            return True

    print()
    print(hdr("─" * 50))
    print(hdr("  Step 1 / 2 - Data preprocessing"))
    print(hdr("─" * 50))
    result = subprocess.run(
        [sys.executable, str(BASE_DIR / "src" / "data_pipeline.py")],
        cwd=BASE_DIR,
    )
    if result.returncode != 0:
        print(err("data_pipeline.py failed. Check the output above."))
        return False

    print()
    print(hdr("─" * 50))
    print(hdr("  Step 2 / 2 - Model training"))
    print(hdr("─" * 50))
    result = subprocess.run(
        [sys.executable, str(BASE_DIR / "src" / "model_trainer.py")],
        cwd=BASE_DIR,
    )
    if result.returncode != 0:
        print(err("model_trainer.py failed. Check the output above."))
        return False

    print()
    print(ok("Training complete."))
    return True


# ---------------------------------------------------------------------------
# System start
# ---------------------------------------------------------------------------

def start_system(extra_args: Optional[List[str]] = None) -> None:
    """
    Import and invoke ``main.main()``.

    Importing rather than subprocess-spawning keeps everything in the same
    process so log output is unified and Ctrl+C propagates correctly.

    Args:
        extra_args: Additional CLI arguments forwarded to ``main.parse_args()``.
    """
    if extra_args:
        sys.argv = [sys.argv[0], *extra_args]
    else:
        # Reset sys.argv so main.py only sees its own script name
        # (this prevents run.py's args like --skip-checks from leaking through)
        sys.argv = [sys.argv[0]]

    try:
        import main as _main
        _main.main()
    except ImportError as exc:
        print(err(f"Import error: {exc}"))
        print("Install dependencies:  pip install -r requirements.txt")
        sys.exit(1)
    except KeyboardInterrupt:
        print()
        print(ok("System stopped by user."))
    except SystemExit as exc:
        sys.exit(exc.code)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="run.py",
        description="DDoS Detection & Mitigation System — Quick-Start Launcher",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples\n"
            "--------\n"
            "  python run.py                      # auto-train if needed, then start\n"
            "  python run.py --train              # force retrain, then start\n"
            "  python run.py --check              # dependency check only\n"
            "  python run.py --no-block           # detection only, no firewall\n"
            "  python run.py --interface eth0     # custom capture interface\n"
            "  python run.py -- --debug --cv-folds 5  # extra args forwarded to main.py\n"
        ),
    )
    p.add_argument("--train",     action="store_true",
                   help="Force model retraining before starting.")
    p.add_argument("--check",     action="store_true",
                   help="Run dependency and model checks then exit.")
    p.add_argument("--no-block",  action="store_true",
                   help="Disable automatic IP blocking.")
    p.add_argument("--interface", type=str, default=None,
                   help="Network interface for packet capture.")
    p.add_argument("--skip-checks", action="store_true",
                   help="Skip dependency checks (faster startup).")
    # Anything after '--' lands in extra_args
    p.add_argument("extra_args",  nargs=argparse.REMAINDER,
                   help="Extra arguments forwarded verbatim to main.py.")
    return p


def _prompt(question: str, default: str = "Y") -> str:
    """Print a Y/N prompt and return the stripped user input."""
    indicator = "[Y/n]" if default.upper() == "Y" else "[y/N]"
    try:
        return input(f"  {question} {indicator}: ").strip() or default
    except (EOFError, KeyboardInterrupt):
        return default


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    parser = _build_parser()
    args   = parser.parse_args()
    deps_ok = True

    # Strip leading '--' sentinel and internal run.py flags that shouldn't go to main.py
    extra = [a for a in (args.extra_args or []) if a != "--" and a != "--skip-checks"]

    # ── Append CLI flags to extra_args for main.py ──────────────────────
    if args.no_block  and "--no-block"  not in extra: extra.append("--no-block")
    if args.interface and "--interface" not in extra:
        extra += ["--interface", args.interface]

    # ── Banner ───────────────────────────────────────────────────────────
    print()
    print(hdr("=" * 52))
    print(hdr("   DDoS Detection & Mitigation System"))
    print(hdr("=" * 52))
    print()

    # ── Dependency checks ────────────────────────────────────────────────
    if not args.skip_checks:
        print(hdr("[ Dependency Check ]"))
        if not check_python_version():
            sys.exit(1)

        deps_ok, missing = check_packages()
        if not deps_ok:
            installed = offer_install(missing)
            if not installed:
                print(err("Cannot start with missing dependencies."))
                sys.exit(1)
    else:
        print(info("Dependency checks skipped (--skip-checks)."))

    print()

    # ── Model check ──────────────────────────────────────────────────────
    print(hdr("[ Model Status ]"))
    models_ok = check_models()

    if args.check:
        # --check: report and exit
        print()
        if deps_ok and models_ok:
            print(ok("All checks passed. System is ready."))
        else:
            print(warn("Some checks failed - see above."))
        return

    print()

    # ── Training ─────────────────────────────────────────────────────────
    if args.train or not models_ok:
        if not models_ok and not args.train:
            print(warn("No trained models found."))
            choice = _prompt("Train models now?", default="Y")
            if choice.lower() != "y":
                print()
                print(warn("Starting without trained models - detection will not function."))
                _prompt("Press Enter to continue anyway", default="")
            else:
                if not run_training(force=False):
                    sys.exit(1)
        else:
            # --train flag: always retrain
            if not run_training(force=args.train):
                sys.exit(1)

    # ── Start system ─────────────────────────────────────────────────────
    print()
    print(hdr("[ Starting System ]"))
    print(info(f"  Dashboard  :  http://localhost:8000/dashboard"))
    print(info(f"  API docs   :  http://localhost:8000/docs"))
    print(info(f"  WebSocket  :  ws://localhost:8000/ws/dashboard"))
    print(info( "  Press Ctrl+C to stop"))
    print()

    start_system(extra_args=extra if extra else None)


if __name__ == "__main__":
    main()
