#!/usr/bin/env python3
"""
Venv Hook — Activates stillrunning protection across virtual environments.

This module is designed to be imported from sitecustomize.py to ensure
stillrunning's import hook remains active even after activating a venv.

When imported:
1. Checks if stillrunning is available
2. Activates the import hook
3. Exits gracefully if anything fails (never breaks Python startup)

Usage:
    # In ~/.local/lib/python3.x/site-packages/sitecustomize.py:
    try:
        import stillrunning.venv_hook
    except ImportError:
        pass
"""

import sys
import os

# Marker to prevent double-initialization
_VENV_HOOK_INITIALIZED = False


def _should_skip() -> bool:
    """Check if we should skip hook activation."""
    if os.environ.get("STILLRUNNING_DISABLE", "").lower() in ("1", "true", "yes"):
        return True
    if os.environ.get("STILLRUNNING_DEV", "").lower() in ("1", "true", "yes"):
        return True
    return False


def _activate_hook():
    """Activate the stillrunning import hook if available."""
    global _VENV_HOOK_INITIALIZED

    if _VENV_HOOK_INITIALIZED:
        return

    if _should_skip():
        return

    try:
        from stillrunning import hook
        if not hook.is_installed():
            hook.install()
        _VENV_HOOK_INITIALIZED = True
    except ImportError:
        pass
    except Exception:
        pass


_activate_hook()
