"""OSV.dev client for known-vulnerability (CVE) checks. Stdlib only, no
package-relative imports: the Claude Code hook runs claude_hook.py as a bare
script (`python -I -S`) and loads this file by path, and only when a command
actually installs something.

Talks to https://api.osv.dev and nothing else (redirects are refused). Sends
package names, ecosystems and versions — never file contents or paths.

Nothing OSV says is passed on as text. A vulnerability is reduced to its id,
alias ids, a severity word, the first fixed version and the modified time,
each matched against a strict pattern; summaries and details are dropped.

Severity: the GitHub Advisory word (`database_specific.severity`, delivered
through OSV for GHSA records) when present, else the CVSS v3 base score
computed from the vector, else a CVSS v4 record's stated numeric score, else
None (= unknown severity).
"""
import json
import math
import re
import urllib.request

HOST = "https://api.osv.dev"
USER_AGENT = "stillrunning-cve/1"
ECOSYSTEM = {"pip": "PyPI", "npm": "npm"}
BATCH_MAX = 1000
SEVERITIES = ("LOW", "MODERATE", "HIGH", "CRITICAL")
RANK = {None: 0, "LOW": 1, "MODERATE": 2, "HIGH": 3, "CRITICAL": 4}

SAFE_ID = re.compile(r"^[A-Z][A-Z0-9]{1,15}-[A-Za-z0-9][A-Za-z0-9._:-]{1,60}$")
SAFE_VERSION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+!-]{0,63}$")
SAFE_TIME = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z$")
SAFE_NAME = re.compile(r"^(@[a-z0-9][a-z0-9._~-]*/)?[a-z0-9][a-z0-9._~-]{0,213}$", re.I)

# Fixed words for what went wrong; nothing from the error itself is shown.
WHY = {
    "offline": "api.osv.dev could not be reached",
    "timeout": "api.osv.dev took too long to answer",
    "http": "api.osv.dev answered with an error",
    "garbage": "api.osv.dev sent an answer that could not be read",
    "budget": "the time allowed for the check ran out",
    "version": "the version that would be installed could not be worked out",
    "range": "the command does not name one exact version",
}


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):  # never follow to another host
        return None


def _opener():
    return urllib.request.build_opener(_NoRedirect)


def _call(method, path, body=None, timeout=8.0, opener=None):
    """→ (parsed JSON, None) or (None, why-key). Only api.osv.dev."""
    import socket
    import urllib.error
    import urllib.request
    url = HOST + path
    if not url.startswith(HOST + "/v1/"):
        return None, "http"
    data = json.dumps(body).encode() if body is not None else None
    headers = {"User-Agent": USER_AGENT, "Accept": "application/json"}
    if data is not None:
        headers["Content-Type"] = "application/json"
    request = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with (opener or _opener()).open(request, timeout=timeout) as response:
            raw = response.read(30_000_000)
    except urllib.error.HTTPError:
        return None, "http"
    except (socket.timeout, TimeoutError):
        return None, "timeout"
    except urllib.error.URLError as exc:
        return None, "timeout" if isinstance(getattr(exc, "reason", None),
                                             (socket.timeout, TimeoutError)) else "offline"
    except (OSError, ValueError):
        return None, "offline"
    try:
        parsed = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return None, "garbage"
    return (parsed, None) if isinstance(parsed, dict) else (None, "garbage")


# ─────────────────────────────── CVSS ───────────────────────────────
_V3 = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "UI": {"N": 0.85, "R": 0.62},
    "C": {"H": 0.56, "L": 0.22, "N": 0.0},
    "I": {"H": 0.56, "L": 0.22, "N": 0.0},
    "A": {"H": 0.56, "L": 0.22, "N": 0.0},
}
_PR = {"U": {"N": 0.85, "L": 0.62, "H": 0.27}, "C": {"N": 0.85, "L": 0.68, "H": 0.5}}


def _roundup(value):
    """CVSS v3.1 Roundup: the smallest number with one decimal >= value."""
    whole = int(round(value * 100000))
    if whole % 10000 == 0:
        return whole / 100000.0
    return (math.floor(whole / 10000) + 1) / 10.0


def cvss3_base_score(vector):
    """Base score of a CVSS v3.0/v3.1 vector, or None when it is not one."""
    if not isinstance(vector, str) or not re.match(r"^CVSS:3\.[01]/", vector):
        return None
    metrics = {}
    for part in vector.split("/")[1:]:
        if ":" not in part:
            return None
        key, value = part.split(":", 1)
        metrics[key] = value
    try:
        scope = metrics["S"]
        if scope not in ("U", "C"):
            return None
        av, ac, ui = _V3["AV"][metrics["AV"]], _V3["AC"][metrics["AC"]], _V3["UI"][metrics["UI"]]
        pr = _PR[scope][metrics["PR"]]
        c, i, a = _V3["C"][metrics["C"]], _V3["I"][metrics["I"]], _V3["A"][metrics["A"]]
    except KeyError:
        return None
    iss = 1 - (1 - c) * (1 - i) * (1 - a)
    if scope == "U":
        impact = 6.42 * iss
    else:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    exploitability = 8.22 * av * ac * pr * ui
    if impact <= 0:
        return 0.0
    if scope == "U":
        return _roundup(min(impact + exploitability, 10))
    return _roundup(min(1.08 * (impact + exploitability), 10))


def band(score):
    """CVSS score → severity word (None for 0.0 or no score)."""
    if not isinstance(score, (int, float)) or isinstance(score, bool) or score <= 0:
        return None
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MODERATE"
    return "LOW"


def severity_of(raw):
    """One OSV record → severity word or None (unknown)."""
    db = raw.get("database_specific") if isinstance(raw.get("database_specific"), dict) else {}
    word = str(db.get("severity") or "").upper()
    if word == "MEDIUM":
        word = "MODERATE"
    if word in SEVERITIES:
        return word
    best = None
    for entry in raw.get("severity") if isinstance(raw.get("severity"), list) else []:
        if not isinstance(entry, dict):
            continue
        kind, score = entry.get("type"), entry.get("score")
        found = None
        if kind == "CVSS_V3":
            found = band(cvss3_base_score(score))
        elif kind == "CVSS_V4":
            try:                       # only a stated number; a v4 vector is not computed here
                found = band(float(score))
            except (TypeError, ValueError):
                found = None
        if RANK[found] > RANK[best]:
            best = found
    return best


# ─────────────────────────────── versions ───────────────────────────────
def _vkey(version):
    match = re.match(r"^v?(\d+(?:\.\d+)*)(.*)$", str(version or "").strip().lower())
    if not match:
        return None
    nums = tuple(int(n) for n in match.group(1).split("."))
    while len(nums) > 1 and nums[-1] == 0:
        nums = nums[:-1]
    rest = match.group(2).lstrip(".-_")
    if rest.startswith("+") or rest.startswith("post"):
        tail = (2, rest)
    elif rest:
        tail = (0, rest)             # a pre-release sorts before the release
    else:
        tail = (1, "")
    return nums, tail


def first_fixed(fixed, version):
    """The smallest fixed version above `version` (or the smallest at all
    when the version is unknown)."""
    keyed = [(k, f) for f in fixed for k in [_vkey(f)] if k is not None]
    if not keyed:
        return None
    current = _vkey(version) if version else None
    later = [(k, f) for k, f in keyed if current is None or k > current]
    return min(later)[1] if later else None


def summarize(raw, eco, name, version=None):
    """One OSV record → the validated fields we keep, or None when the record
    is unusable. Nothing else from the record survives."""
    if not isinstance(raw, dict):
        return None
    vid = str(raw.get("id") or "")
    if not SAFE_ID.match(vid):
        return None
    aliases = [str(a) for a in raw.get("aliases") or [] if isinstance(a, str) and SAFE_ID.match(a)]
    want_eco, want = ECOSYSTEM.get(eco), _norm(eco, name)
    fixed = []
    for affected in raw.get("affected") if isinstance(raw.get("affected"), list) else []:
        if not isinstance(affected, dict):
            continue
        package = affected.get("package") if isinstance(affected.get("package"), dict) else {}
        if package.get("ecosystem") != want_eco or _norm(eco, str(package.get("name") or "")) != want:
            continue
        for rng in affected.get("ranges") if isinstance(affected.get("ranges"), list) else []:
            if not isinstance(rng, dict) or rng.get("type") == "GIT":
                continue
            for event in rng.get("events") if isinstance(rng.get("events"), list) else []:
                value = event.get("fixed") if isinstance(event, dict) else None
                if isinstance(value, str) and SAFE_VERSION.match(value):
                    fixed.append(value)
    modified = str(raw.get("modified") or "")
    return {"id": vid, "aliases": aliases[:20], "severity": severity_of(raw),
            "fixed": first_fixed(fixed, version), "fixed_all": sorted(set(fixed))[:20],
            "modified": modified if SAFE_TIME.match(modified) else None,
            "malicious": vid.startswith("MAL-"),
            "withdrawn": bool(raw.get("withdrawn"))}


def _norm(eco, name):
    name = name.strip().lower()
    return re.sub(r"[-_.]+", "-", name) if eco == "pip" else name


def display_id(ids):
    """CVE first, then GHSA, then whatever else (all already validated)."""
    for prefix in ("CVE-", "GHSA-"):
        for vid in ids:
            if vid.startswith(prefix):
                return vid
    return sorted(ids)[0] if ids else None


def cluster(vulns, version=None):
    """The same issue under several ids (PYSEC + GHSA + CVE) counts once.
    → [{"id", "ids", "severity", "fixed"}], worst first."""
    groups = []
    for v in vulns:
        if not v or v.get("malicious") or v.get("withdrawn"):
            continue
        names = {v["id"], *v.get("aliases", [])}
        joined = [g for g in groups if g["names"] & names]
        merged = {"names": set(names), "members": [v]}
        for g in joined:
            merged["names"] |= g["names"]
            merged["members"] += g["members"]
            groups.remove(g)
        groups.append(merged)
    out = []
    for g in groups:
        ghsa = [m["severity"] for m in g["members"] if m["id"].startswith("GHSA-") and m["severity"]]
        sev = ghsa[0] if ghsa else max((m["severity"] for m in g["members"]),
                                       key=lambda s: RANK[s], default=None)
        fixed = first_fixed([f for m in g["members"] for f in m.get("fixed_all") or []], version)
        ids = sorted(g["names"])
        out.append({"id": display_id(ids), "ids": ids[:12], "severity": sev, "fixed": fixed})
    out.sort(key=lambda c: (-RANK[c["severity"]], c["id"]))
    return out


def worst(clusters):
    return max((c["severity"] for c in clusters), key=lambda s: RANK[s], default=None)


# ─────────────────────────────── queries ───────────────────────────────
def query_package(eco, name, version, timeout=6.0, pages=3, opener=None):
    """POST /v1/query for one package (and version, when given) → (list of
    full OSV records, None) or (None, why-key). Used by the install-time
    check: one request returns the records with severity and fixed versions."""
    if eco not in ECOSYSTEM or not SAFE_NAME.match(name or "") or (
            version is not None and not SAFE_VERSION.match(version)):
        return None, "garbage"
    body = {"package": {"name": name, "ecosystem": ECOSYSTEM[eco]}}
    if version:
        body["version"] = version
    records = []
    for _ in range(pages):
        answer, why = _call("POST", "/v1/query", body, timeout, opener)
        if why:
            return None, why
        vulns = answer.get("vulns", [])
        if not isinstance(vulns, list):
            return None, "garbage"
        records += vulns
        token = answer.get("next_page_token")
        if not token:
            return records, None
        if not isinstance(token, str) or len(token) > 2000:
            return None, "garbage"
        body = dict(body, page_token=token)
    return None, "budget"


def query_batch(items, timeout=20.0, opener=None, deadline=None, clock=None):
    """POST /v1/querybatch for [(eco, name, version)] (paginating on
    next_page_token) → (results, failures). `results[i]` is a list of
    (id, modified) for item i, or None when item i could not be checked."""
    import time
    clock = clock or time.monotonic
    results = [None] * len(items)
    failures = []
    for start in range(0, len(items), BATCH_MAX):
        chunk = list(range(start, min(start + BATCH_MAX, len(items))))
        pending = {i: None for i in chunk}          # index → page token
        found = {i: [] for i in chunk}
        rounds = 0
        while pending and rounds < 20:
            rounds += 1
            if deadline is not None and clock() > deadline:
                failures.append("budget")
                break
            order = list(pending)
            queries = []
            for i in order:
                eco, name, version = items[i]
                q = {"package": {"name": name, "ecosystem": ECOSYSTEM[eco]}, "version": version}
                if pending[i]:
                    q["page_token"] = pending[i]
                queries.append(q)
            answer, why = _call("POST", "/v1/querybatch", {"queries": queries}, timeout, opener)
            rows = answer.get("results") if answer else None
            if why or not isinstance(rows, list) or len(rows) != len(order):
                failures.append(why or "garbage")
                break
            pending = {}
            for i, row in zip(order, rows):
                row = row if isinstance(row, dict) else {}
                vulns = row.get("vulns") or []
                if not isinstance(vulns, list):
                    failures.append("garbage")
                    found[i] = None
                    continue
                for v in vulns:
                    vid = str(v.get("id") or "") if isinstance(v, dict) else ""
                    mod = str(v.get("modified") or "") if isinstance(v, dict) else ""
                    if SAFE_ID.match(vid) and found[i] is not None:
                        found[i].append((vid, mod if SAFE_TIME.match(mod) else None))
                    elif found[i] is not None:
                        failures.append("garbage")
                        found[i] = None     # an id we cannot use: this package is not checked
                token = row.get("next_page_token")
                if token and found[i] is not None:
                    if isinstance(token, str) and len(token) <= 2000:
                        pending[i] = token
                    else:
                        failures.append("garbage")
                        found[i] = None
        for i in chunk:
            if i not in pending and found[i] is not None:
                results[i] = found[i]
    return results, failures


def get_vuln(vid, timeout=10.0, opener=None):
    """GET /v1/vulns/{id} → (raw record, None) or (None, why-key)."""
    if not SAFE_ID.match(vid or ""):
        return None, "garbage"
    return _call("GET", "/v1/vulns/" + vid, None, timeout, opener)
