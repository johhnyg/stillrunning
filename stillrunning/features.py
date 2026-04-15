#!/usr/bin/env python3
"""
Feature gating for StillRunning tiers.

Validates customer token against stillrunning.io API and caches result.
Provides feature checks for tier-gated functionality.

Tiers:
- Personal ($9/mo): process monitor, restart, alerts
- Basic ($29/mo): + file integrity, tripwire, honeypot
- AI ($49/mo): + AI package review (server-side)
- Enterprise ($499/mo): everything + unlimited scans, SIEM, SSO, compliance
"""

import json
import time
import urllib.request
from pathlib import Path

# Cache file location
CACHE_FILE = Path.home() / ".stillrunning_token_cache.json"
CACHE_TTL = 3600  # 1 hour
OFFLINE_GRACE_PERIOD = 86400  # 24 hours - use stale cache if API unreachable
API_URL = "https://stillrunning.io/api/validate-token"

# Feature definitions by tier
TIER_FEATURES = {
    "personal": ["process_monitor", "restart", "alerts"],
    "basic": ["process_monitor", "restart", "alerts", "file_integrity", "tripwire", "honeypot"],
    "ai": ["process_monitor", "restart", "alerts", "file_integrity", "tripwire", "honeypot", "ai_review", "central"],
    "team": ["process_monitor", "restart", "alerts", "file_integrity", "tripwire", "honeypot", "ai_review", "central", "rbac"],
    "enterprise": ["process_monitor", "restart", "alerts", "file_integrity", "tripwire", "honeypot", "ai_review", "central", "rbac", "siem", "sso", "compliance", "unlimited_scans"],
    "enterprise_plus": ["process_monitor", "restart", "alerts", "file_integrity", "tripwire", "honeypot", "ai_review", "central", "rbac", "siem", "sso", "compliance", "unlimited_scans", "dedicated_support"],
}

# Default features for unvalidated/free users
FREE_FEATURES = ["process_monitor", "restart", "alerts"]


def _load_cache() -> dict | None:
    """Load cached token validation result."""
    try:
        if CACHE_FILE.exists():
            with open(CACHE_FILE) as f:
                return json.load(f)
    except Exception:
        pass
    return None


def _save_cache(data: dict):
    """Save token validation result to cache atomically."""
    try:
        import os
        tmp_file = Path(str(CACHE_FILE) + ".tmp")
        with open(tmp_file, "w") as f:
            json.dump(data, f, indent=2)
        os.replace(tmp_file, CACHE_FILE)
    except Exception:
        pass


def _call_validate_api(token: str) -> dict:
    """Call stillrunning.io/api/validate-token."""
    try:
        # SECURITY FIX: Send token in header instead of URL query string
        req = urllib.request.Request(
            API_URL,
            headers={
                "User-Agent": "stillrunning-agent/1.9.0",
                "Authorization": f"Bearer {token}"
            }
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        if e.code == 401:
            return {"valid": False, "error": "Invalid token"}
        if e.code == 403:
            return {"valid": False, "error": "Subscription not active"}
        return {"valid": False, "error": f"HTTP {e.code}"}
    except Exception as e:
        return {"valid": False, "error": str(e), "offline": True}


def validate_token(token: str) -> dict:
    """
    Validate token and return tier/features.
    Uses cache with 1-hour TTL and 24-hour offline grace period.

    Returns dict with:
    - valid: bool
    - tier: str (personal/basic/ai/team/enterprise)
    - features: list of feature strings
    - trial: bool
    - trial_days_remaining: int or None
    - scan_limit: int
    - scans_remaining: int
    - cached: bool
    - error: str (if invalid)
    """
    if not token:
        return {
            "valid": False,
            "tier": "free",
            "features": FREE_FEATURES,
            "error": "No token provided"
        }

    # Check cache first
    cache = _load_cache()
    if cache and cache.get("token") == token:
        cached_at = cache.get("cached_at", 0)
        age = time.time() - cached_at

        # Fresh cache (< 1 hour)
        if age < CACHE_TTL:
            cache["cached"] = True
            return cache

        # Stale but within grace period - try API, fall back to cache
        if age < OFFLINE_GRACE_PERIOD:
            result = _call_validate_api(token)
            if result.get("offline"):
                # API unreachable, use stale cache
                cache["cached"] = True
                cache["stale"] = True
                return cache
            # API succeeded, update cache
            result["cached_at"] = time.time()
            result["token"] = token
            result["cached"] = False
            if "features" not in result and result.get("valid"):
                result["features"] = TIER_FEATURES.get(result.get("tier", "personal"), FREE_FEATURES)
            _save_cache(result)
            return result

    # No valid cache - call API
    result = _call_validate_api(token)

    if result.get("offline"):
        # API unreachable and no valid cache
        return {
            "valid": False,
            "tier": "free",
            "features": FREE_FEATURES,
            "error": "Cannot reach stillrunning.io - running in free mode",
            "offline": True
        }

    # Success - cache result
    if result.get("valid"):
        result["cached_at"] = time.time()
        result["token"] = token
        result["cached"] = False
        if "features" not in result:
            result["features"] = TIER_FEATURES.get(result.get("tier", "personal"), FREE_FEATURES)
        _save_cache(result)
    else:
        result["features"] = FREE_FEATURES

    return result


def has_feature(features: list, feature: str) -> bool:
    """Check if a feature is in the features list."""
    return feature in (features or [])


def require_feature(features: list, feature: str, feature_name: str = None) -> bool:
    """
    Check if feature is available.
    Prints upgrade message if not available.
    Returns True if available, False otherwise.
    """
    if has_feature(features, feature):
        return True

    display_name = feature_name or feature.replace("_", " ").title()
    print(f"\n\u26A0\uFE0F  {display_name} requires a paid subscription")
    print(f"   Upgrade at https://stillrunning.io/pricing\n")
    return False


def get_tier_name(tier: str) -> str:
    """Get display name for tier."""
    names = {
        "personal": "Personal ($9/mo)",
        "basic": "Basic ($29/mo)",
        "ai": "AI ($49/mo)",
        "team": "Team ($149/mo)",
        "enterprise": "Enterprise ($499/mo)",
        "enterprise_plus": "Enterprise+ ($2,499/mo)",
    }
    return names.get(tier, tier.title())


def print_tier_status(result: dict):
    """Print current tier status to console."""
    if not result.get("valid"):
        print("\u274C Token invalid or expired")
        if result.get("error"):
            print(f"   Error: {result['error']}")
        print("   Running in free mode (process monitor + alerts only)")
        return

    tier = result.get("tier", "personal")
    print(f"\u2705 Tier: {get_tier_name(tier)}")

    if result.get("trial"):
        days = result.get("trial_days_remaining", 0)
        print(f"   Trial: {days} days remaining")

    if result.get("cached"):
        if result.get("stale"):
            print("   (cached - API unreachable)")
        else:
            print("   (cached)")

    features = result.get("features", [])
    if "ai_review" in features:
        remaining = result.get("scans_remaining", 0)
        limit = result.get("scan_limit", 0)
        print(f"   AI Scans: {remaining}/{limit} remaining today")
