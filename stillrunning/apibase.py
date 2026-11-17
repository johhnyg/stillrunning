"""Where the stillrunning API lives.

Default: https://stillrunning.io. The environment variable
STILLRUNNING_API_BASE can point the client at a test server ON THIS MACHINE
only (localhost / 127.0.0.1 / ::1, http or https). Any other host is refused
with a warning and the default is used: an override to another host would let
whoever sets one variable answer every lookup ("not on the blocklist") and
collect the account token. The token is never sent to a non-default base
(see token_allowed).
"""
import os
import sys
import urllib.parse

DEFAULT_API_BASE = "https://stillrunning.io"
ENV_VAR = "STILLRUNNING_API_BASE"
_LOOPBACK = {"localhost", "127.0.0.1", "::1"}
_warned = set()


def _warn(msg: str) -> None:
    if msg not in _warned:
        _warned.add(msg)
        print(f"[stillrunning] WARNING: {msg}", file=sys.stderr)


def api_base() -> str:
    """Base URL without a trailing slash."""
    raw = (os.environ.get(ENV_VAR) or "").strip()
    if not raw:
        return DEFAULT_API_BASE
    try:
        parsed = urllib.parse.urlsplit(raw)
        host = parsed.hostname or ""
    except ValueError:
        parsed, host = None, ""
    ok = (parsed is not None and host.lower() in _LOOPBACK and not parsed.username
          and parsed.scheme in ("http", "https"))
    if not ok:
        _warn(f"{ENV_VAR}={raw!r} refused (only a test server on this machine is "
              f"accepted: localhost, 127.0.0.1 or ::1); using {DEFAULT_API_BASE}")
        return DEFAULT_API_BASE
    return raw.rstrip("/")


def token_allowed() -> bool:
    """The account token goes to the default server and nowhere else."""
    return api_base() == DEFAULT_API_BASE


def is_overridden() -> bool:
    return api_base() != DEFAULT_API_BASE


def api_url(path: str) -> str:
    """api_url('/api/check-package') -> full URL on the configured base."""
    return api_base() + (path if path.startswith("/") else "/" + path)
