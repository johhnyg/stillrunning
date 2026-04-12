"""
stillrunning - Enterprise security and monitoring for developers.
Auto-restart, threat detection, pkl inspector, supply chain protection.

Patent Pending - US Provisional Application filed April 12, 2026

Usage:
    stillrunning --setup          # 3-minute setup wizard
    stillrunning-scan <file>      # Static analysis scanner
    stillrunning-guard            # Always-on security daemon
    stillrunning-intercept        # npm/pip supply chain blocker
    pkl-inspector <file>          # Pickle file static analysis
"""

__version__ = "1.7.0"
__author__ = "johhnyg"
__license__ = "MIT"

# Re-export main components
from .cli import main_cli, load_config
from .scan import main as scan_main, analyze_python_file, analyze_pickle_file
from .guard import main_loop as guard_main
from .intercept import main as intercept_main
from .docker_agent import main as docker_main
from .pkl_inspector import PklInspector, main as pkl_main

__all__ = [
    "__version__",
    "main_cli",
    "load_config",
    "scan_main",
    "analyze_python_file",
    "analyze_pickle_file",
    "guard_main",
    "intercept_main",
    "docker_main",
    "PklInspector",
    "pkl_main",
]
