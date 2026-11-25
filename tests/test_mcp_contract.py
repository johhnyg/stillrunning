"""The hosted MCP server (https://stillrunning.io/mcp) tested three ways.

1. Contract parity: the local hook's verdict for a package against the MCP
   server's, for known-malicious, popular and made-up names.
2. Input fuzzing (Hypothesis) of the MCP server's JSON-RPC route.
3. Unreachable server: what a caller gets when the lookup cannot complete,
   recorded rather than judged.

Every network part is opt-in, so CI and a plain `pytest` run collect this
module, run the offline parts and skip the rest:

  STILLRUNNING_MCP_CONTRACT_URL  MCP endpoint for the contract test
                                 (production is fine: the call budget below)
  STILLRUNNING_MCP_BUDGET        max MCP calls the contract test makes (default 30)
  STILLRUNNING_MCP_LOCAL_URL     MCP endpoint to FUZZ: a local instance only;
                                 stillrunning.io is refused
  STILLRUNNING_MCP_REPORT        file to append one JSON line per observation to

Verdict classes compared (both sides mapped to the same five):
  BLOCKED     MCP verdict BLOCKED          | hook lookup status "blocked"
  SUSPICIOUS  MCP verdict SUSPICIOUS       | hook "suspicious" or "not_found"
  UNKNOWN     MCP UNKNOWN, a real check    | hook "ok" (not on the list)
  UNVERIFIED  MCP UNKNOWN status error/stale_data/invalid_name | hook "unverified"
  NO_ANSWER   MCP quota or JSON-RPC error  | (not compared)
"""
import http.client
import json
import os
import random
import socket
import subprocess
import sys
import threading
import time
import urllib.parse
import urllib.request

import pytest

_REAL_URLOPEN = urllib.request.urlopen      # tests/conftest.py stubs it for every test
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HOOK = os.path.join(ROOT, "stillrunning", "claude_hook.py")

CONTRACT_URL = os.environ.get("STILLRUNNING_MCP_CONTRACT_URL", "").strip()
LOCAL_URL = os.environ.get("STILLRUNNING_MCP_LOCAL_URL", "").strip()
BUDGET = int(os.environ.get("STILLRUNNING_MCP_BUDGET", "30"))
# The hook's unmetered fallback route is rate-limited at the edge (about 20
# requests in a few seconds per address); pace the hook side to stay under it.
PACE_S = float(os.environ.get("STILLRUNNING_MCP_PACE_S", "1.2"))
REPORT = os.environ.get("STILLRUNNING_MCP_REPORT", "").strip()
FUZZ_TIMEOUT_S = 15.0

# Publicly listed malicious pip packages (blocklist, 2026-11-25): listed for every
# version, listed for some versions only, and other spellings of listed names.
MALICIOUS_ALL_VERSIONS = [
    "beautifusoup", "cpuvirtual", "esqminelib", "gitpythno", "grandinfo", "libhydraregame",
    "libmcmine", "postrandom", "py-osintmcurl", "py-replacepushinfo", "selfccverosint",
    "selfloadgrand", "tpintpaypalcc", "vinnleys",
]
MALICIOUS_SOME_VERSIONS = ["afritonpy", "jobwharf", "testing1345py", "trongridme"]
MALICIOUS_SPELLINGS = ["BeautifuSoup", "py_osintmcurl"]
MALICIOUS = MALICIOUS_ALL_VERSIONS + MALICIOUS_SOME_VERSIONS + MALICIOUS_SPELLINGS
# Popular packages, all on the server's trusted-core list (no AI review is run for them).
POPULAR = [
    "requests", "numpy", "pandas", "flask", "django", "boto3", "urllib3", "setuptools", "pip",
    "certifi", "idna", "charset-normalizer", "pyyaml", "click", "jinja2", "pytest", "attrs",
    "packaging", "wheel", "cryptography",
]
_rnd = random.Random(20261125)
UNKNOWN_NAMES = ["srct-%08x" % _rnd.getrandbits(32) for _ in range(20)]   # valid names, not on PyPI


def _record(kind, **row):
    row = dict(kind=kind, **row)
    if REPORT:
        with open(REPORT, "a", encoding="utf-8") as handle:
            handle.write(json.dumps(row, sort_keys=True) + "\n")
    return row


# ── MCP client (http.client: urllib is stubbed by conftest) ──

def mcp_post(url, payload, timeout=20.0, headers=None, raw=None):
    """→ (HTTP status or None, body bytes, seconds, exception name or None)."""
    parts = urllib.parse.urlsplit(url)
    conn_cls = http.client.HTTPSConnection if parts.scheme == "https" else http.client.HTTPConnection
    body = raw if raw is not None else json.dumps(payload).encode("utf-8")
    start = time.monotonic()
    try:
        conn = conn_cls(parts.hostname, parts.port, timeout=timeout)
        conn.request("POST", parts.path or "/", body=body,
                     headers=dict({"Content-Type": "application/json", "Accept": "application/json",
                                   "User-Agent": "stillrunning-mcp-contract-tests"}, **(headers or {})))
        resp = conn.getresponse()
        data = resp.read()
        conn.close()
        return resp.status, data, time.monotonic() - start, None
    except Exception as exc:            # recorded by the caller: an outage is data here
        return None, b"", time.monotonic() - start, type(exc).__name__


def tool_call(name, version=None, rpc_id=1):
    args = {"package_name": name}
    if version is not None:
        args["version"] = version
    return {"jsonrpc": "2.0", "id": rpc_id, "method": "tools/call",
            "params": {"name": "check_package", "arguments": args}}


def mcp_verdict(url, name, headers=None, timeout=20.0):
    status, data, secs, exc = mcp_post(url, tool_call(name), timeout=timeout, headers=headers)
    out = {"http": status, "secs": round(secs, 2), "exception": exc}
    try:
        reply = json.loads(data.decode("utf-8")) if data else None
    except ValueError:
        reply = None
    result = (reply or {}).get("result") or {}
    text = ((result.get("content") or [{}])[0] or {}).get("text", "")
    try:
        verdict = json.loads(text)
    except ValueError:
        verdict = None
    if isinstance(verdict, dict) and "verdict" in verdict:
        out.update(verdict=verdict.get("verdict"), status=verdict.get("status"),
                   action=verdict.get("action"))
    else:
        out.update(verdict=None, error=(text or json.dumps((reply or {}).get("error")))[:200])
    out["cls"] = mcp_class(out)
    return out


def mcp_class(out):
    verdict, status = out.get("verdict"), out.get("status")
    if verdict == "BLOCKED":
        return "BLOCKED"
    if verdict == "SUSPICIOUS":
        return "SUSPICIOUS"
    if verdict == "UNKNOWN":
        return "UNVERIFIED" if status in ("error", "stale_data", "invalid_name") else "UNKNOWN"
    return "NO_ANSWER"


# ── the local hook's verdict (its real lookup: stillrunning.io + the registry) ──

def hook_verdict(name):
    from stillrunning import claude_hook as ch
    result = ch.lookup({"eco": "pip", "name": name, "version": None})
    status = result.get("status")
    cls = {"blocked": "BLOCKED", "override_blocked": "BLOCKED", "suspicious": "SUSPICIOUS",
           "not_found": "SUSPICIOUS", "ok": "UNKNOWN", "unverified": "UNVERIFIED"}.get(status, "UNVERIFIED")
    if status == "ok" and result.get("registry") is False:
        cls = "SUSPICIOUS"                 # not on the registry: the hook asks, the MCP says not_on_pypi
    return {"status": status, "why": result.get("why"), "registry": result.get("registry"), "cls": cls}


# ── 1. contract parity ──

@pytest.mark.skipif(not CONTRACT_URL, reason="set STILLRUNNING_MCP_CONTRACT_URL to run the contract test")
def test_hook_and_mcp_return_the_same_verdict(monkeypatch, tmp_path):
    monkeypatch.setattr(urllib.request, "urlopen", _REAL_URLOPEN)
    monkeypatch.setenv("STILLRUNNING_CVE_CHECK", "0")
    monkeypatch.setenv("HOME", str(tmp_path))              # anonymous, like the MCP caller: no account token,
    monkeypatch.setenv("USERPROFILE", str(tmp_path))       # no overrides or caches from this machine
    # A local instance sees each caller by X-Real-IP (no nginx in front): a fresh
    # one per call keeps its quota out of the comparison. Production ignores it.
    rotate = not (urllib.parse.urlsplit(CONTRACT_URL).hostname or "").endswith("stillrunning.io")
    # Budget order: the anonymous MCP quota (10 a day) goes to the popular names;
    # known-malicious names are answered past the quota; made-up names come last.
    sample = [("popular", n) for n in POPULAR] + [("malicious", n) for n in MALICIOUS] + \
             [("unknown", n) for n in UNKNOWN_NAMES]
    rows, calls = [], 0
    for group, name in sample:
        if calls >= BUDGET:
            rows.append(_record("contract", group=group, name=name, skipped="budget"))
            continue
        time.sleep(PACE_S)
        hook = hook_verdict(name)
        mcp = mcp_verdict(CONTRACT_URL, name, headers=_fresh_client() if rotate else None)
        calls += 1
        same = mcp["cls"] == "NO_ANSWER" or hook["cls"] == mcp["cls"]
        rows.append(_record("contract", group=group, name=name, hook=hook, mcp=mcp, same=same))
    compared = [r for r in rows if "mcp" in r and r["mcp"]["cls"] != "NO_ANSWER"]
    divergent = [r for r in compared if not r["same"]]
    summary = _record("contract_summary", url=CONTRACT_URL, calls=calls, compared=len(compared),
                      no_answer=sum(1 for r in rows if "mcp" in r and r["mcp"]["cls"] == "NO_ANSWER"),
                      skipped=sum(1 for r in rows if "skipped" in r), divergent=len(divergent))
    print(json.dumps(summary))
    for r in divergent:
        print("DIVERGENCE %-22s hook=%s(%s) mcp=%s(%s)" % (
            r["name"], r["hook"]["cls"], r["hook"]["status"], r["mcp"]["cls"], r["mcp"]["status"]))
    assert compared, "no MCP verdict to compare (all quota/errors)"
    assert not divergent, "%d hook/MCP divergences (printed above)" % len(divergent)


# ── 2. input fuzzing (local instance only) ──

def _local_url_or_skip():
    if not LOCAL_URL:
        pytest.skip("set STILLRUNNING_MCP_LOCAL_URL to a LOCAL MCP instance to fuzz it")
    host = (urllib.parse.urlsplit(LOCAL_URL).hostname or "").lower()
    if host.endswith("stillrunning.io"):
        pytest.fail("refusing to fuzz production: point STILLRUNNING_MCP_LOCAL_URL at a local instance")
    return LOCAL_URL


_VERDICTS = {"BLOCKED", "SUSPICIOUS", "UNKNOWN"}
_ACTIONS = {"blocked", "allowed_unreviewed"}
_NOT_VOUCHED = ("not a clean", "not a statement", "nothing was checked", "not verified", "could not",
                "unverified", "not on pypi", "not a confirmed", "not in the", "no match", "do not install")
_counter = {"n": 0}


def _fresh_client():
    """A different caller address per request: the anonymous quota (10 a day per
    address) would otherwise turn every reply after the tenth into a quota error."""
    _counter["n"] += 1
    n = _counter["n"]
    return {"X-Real-IP": "198.18.%d.%d" % ((n >> 8) % 256, n % 256)}


def check_reply(status, data, secs, exc):
    """The fuzz invariants for one reply; → the parsed verdict dict or None."""
    assert exc is None, "request failed: %s after %.1fs" % (exc, secs)
    assert secs < FUZZ_TIMEOUT_S, "reply took %.1fs" % secs
    assert status is not None and status < 500, "HTTP %s" % status
    if status == 202:
        assert data in (b"", None)
        return None
    reply = json.loads(data.decode("utf-8"))            # always JSON
    replies = reply if isinstance(reply, list) else [reply]
    found = None
    for one in replies:
        assert isinstance(one, dict)
        if "error" in one and one["error"] is not None:
            err = one["error"]
            assert isinstance(err.get("code"), int) and isinstance(err.get("message"), str), one
            continue
        result = one.get("result", one)
        content = (result or {}).get("content")
        if not content:
            continue
        text = content[0].get("text", "")
        try:
            verdict = json.loads(text)
        except ValueError:
            # a plain-text tool result: the quota / denied message
            assert text and len(text) < 2000, text
            continue
        assert verdict.get("verdict") in _VERDICTS, verdict
        assert verdict.get("action") in _ACTIONS, verdict
        if verdict["verdict"] in ("BLOCKED", "SUSPICIOUS"):
            assert verdict["action"] == "blocked", verdict
        else:
            # UNKNOWN must never read as safe to install
            assert verdict["action"] == "allowed_unreviewed", verdict
            msg = (verdict.get("agent_message") or "").lower()
            assert any(p in msg for p in _NOT_VOUCHED), "UNKNOWN reads as safe: %r" % msg
        found = verdict
    return found


try:
    from hypothesis import HealthCheck, given, settings, strategies as st
except ImportError:              # CI installs only pytest
    given = None

if given is not None:
    _INJECTION = ["'; DROP TABLE entries; --", "../../../../etc/passwd", "$(id)", "`id`", "<script>x</script>",
                  "{{7*7}}", "%00", "a\r\nX-Injected: 1", "\" OR \"1\"=\"1", "${jndi:ldap://x}", "\\\\x\\y",
                  "requests; rm -rf /", "requests && curl x", "|nc x 1", "‮requests", "req​uests"]
    _FEED_SHAPED = ["MONAI Label", "requests==2.31.0", "requests[security]", "requests>=1,<3",
                    "@evil/pkg", "pkg:pypi/requests@1.0", "GHSA-xxxx-yyyy-zzzz", "MAL-2026-1",
                    "beautifusoup==1.0", "BEAUTIFUSOUP", "beautifu-soup", "beautifu.soup", "beautifu_soup",
                    "py-osintmcurl ", " py-osintmcurl", "py--osintmcurl", "-requests", "requests-", "a", "a" * 214]
    _names = st.one_of(
        st.text(max_size=80),
        st.text(alphabet=st.characters(min_codepoint=0, max_codepoint=0x10FFFF), max_size=40),
        st.text(alphabet="\x00\x01\n\r\t \"'\\/$`{}[]<>;|&", max_size=30),
        st.text(alphabet="abcdefghijklmnopqrstuvwxyz0123456789-_.", min_size=1, max_size=60),
        st.integers(min_value=1, max_value=200000).map(lambda n: "a" * n),
        st.sampled_from(_INJECTION + _FEED_SHAPED + MALICIOUS + POPULAR),
        st.none(), st.integers(), st.floats(allow_nan=True), st.booleans(),
        st.lists(st.text(max_size=5), max_size=3), st.dictionaries(st.text(max_size=5), st.text(max_size=5), max_size=2),
    )
    _versions = st.one_of(st.none(), st.text(max_size=40), st.sampled_from(["1.0", "==1.0", "latest", "", " ", "1.0\x00", "*"]),
                          st.integers())
    _FUZZ = settings(max_examples=int(os.environ.get("STILLRUNNING_MCP_FUZZ_EXAMPLES", "300")), deadline=None,
                     suppress_health_check=list(HealthCheck), derandomize=True)

    @_FUZZ
    @given(name=_names, version=_versions)
    def test_fuzz_check_package_never_crashes_or_vouches(name, version):
        url = _local_url_or_skip()
        payload = tool_call(name, version) if version is not None else tool_call(name)
        status, data, secs, exc = mcp_post(url, payload, timeout=FUZZ_TIMEOUT_S, headers=_fresh_client())
        try:
            check_reply(status, data, secs, exc)
        except AssertionError:
            _record("fuzz_failure", name=repr(name)[:300], version=repr(version)[:100], http=status,
                    secs=round(secs, 2), exception=exc, body=(data or b"")[:300].decode("utf-8", "replace"))
            raise

    _ENVELOPES = st.one_of(
        st.fixed_dictionaries({"jsonrpc": st.sampled_from(["2.0", "1.0", None, 2]),
                               "id": st.one_of(st.none(), st.integers(), st.text(max_size=10)),
                               "method": st.one_of(st.sampled_from(["tools/call", "tools/list", "initialize",
                                                                    "ping", "nope", "", "tools/call\x00"]),
                                                   st.text(max_size=20), st.integers()),
                               "params": st.one_of(st.none(), st.text(max_size=10), st.lists(st.integers(), max_size=3),
                                                   st.fixed_dictionaries({"name": st.one_of(st.sampled_from(["check_package", "x"]), st.text(max_size=10)),
                                                                          "arguments": st.one_of(st.none(), st.text(max_size=5),
                                                                                                 st.dictionaries(st.text(max_size=12), _names, max_size=3))}))}),
        st.lists(st.just(tool_call("requests")), min_size=0, max_size=25),
        st.just("not a dict"), st.integers(), st.none(),
    )

    @_FUZZ
    @given(envelope=_ENVELOPES)
    def test_fuzz_jsonrpc_envelope_never_crashes(envelope):
        url = _local_url_or_skip()
        status, data, secs, exc = mcp_post(url, envelope, timeout=FUZZ_TIMEOUT_S, headers=_fresh_client())
        try:
            check_reply(status, data, secs, exc)
        except AssertionError:
            _record("fuzz_failure", envelope=repr(envelope)[:400], http=status, secs=round(secs, 2),
                    exception=exc, body=(data or b"")[:300].decode("utf-8", "replace"))
            raise

    @_FUZZ
    @given(raw=st.one_of(st.binary(max_size=200), st.just(b""), st.just(b"{"), st.just(b"\xff\xfe{}"),
                         st.just(b"[" * 5000 + b"]" * 5000), st.just(b'{"a":' * 3000 + b"1" + b"}" * 3000)))
    def test_fuzz_raw_bodies_never_crash(raw):
        url = _local_url_or_skip()
        status, data, secs, exc = mcp_post(url, None, timeout=FUZZ_TIMEOUT_S, headers=_fresh_client(), raw=raw)
        try:
            check_reply(status, data, secs, exc)
        except AssertionError:
            _record("fuzz_failure", raw=repr(raw[:200]), http=status, secs=round(secs, 2), exception=exc,
                    body=(data or b"")[:300].decode("utf-8", "replace"))
            raise


def test_fuzz_over_quota_reply_is_well_formed():
    """The realistic 'lookup cannot complete' for an anonymous agent: the 11th call."""
    url = _local_url_or_skip()
    caller = {"X-Real-IP": "198.19.0.%d" % random.Random().randint(1, 254)}
    replies = [mcp_post(url, tool_call("requests"), timeout=FUZZ_TIMEOUT_S, headers=caller) for _ in range(12)]
    for reply in replies:
        check_reply(*reply)
    last = json.loads(replies[-1][1].decode("utf-8"))
    text = last["result"]["content"][0]["text"]
    _record("over_quota", http=replies[-1][0], reply=text[:300], is_error=last["result"].get("isError"))
    print("over-quota reply:", text[:200], "| isError:", last["result"].get("isError"))
    malicious = mcp_post(url, tool_call("beautifusoup"), timeout=FUZZ_TIMEOUT_S, headers=caller)
    verdict = check_reply(*malicious)
    _record("over_quota_malicious", verdict=verdict)
    assert verdict and verdict["verdict"] == "BLOCKED", "a listed package must still be answered past the quota"


# ── 3. unreachable server: measured, not judged ──

def _dead_port():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()                       # nothing listens there now
    return port


class _SilentServer:
    """Accepts connections and never answers: a hung server."""

    def __init__(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(8)
        self.port = self.sock.getsockname()[1]
        self.conns = []
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()

    def _run(self):
        while True:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            self.conns.append(conn)

    def close(self):
        for conn in self.conns:
            conn.close()
        self.sock.close()


def test_unreachable_mcp_server_what_the_caller_gets():
    """Records what an MCP client gets when the lookup cannot complete. There is
    no verdict to read in any of these: the caller gets a transport error."""
    observed = {}
    dead = _dead_port()
    status, data, secs, exc = mcp_post("http://127.0.0.1:%d/mcp" % dead, tool_call("beautifusoup"), timeout=5.0)
    observed["dead_port"] = {"http": status, "exception": exc, "secs": round(secs, 3)}
    silent = _SilentServer()
    try:
        for label, timeout in (("hung_server_1ms_timeout", 0.001), ("hung_server_2s_timeout", 2.0)):
            status, data, secs, exc = mcp_post("http://127.0.0.1:%d/mcp" % silent.port, tool_call("beautifusoup"),
                                               timeout=timeout)
            observed[label] = {"http": status, "exception": exc, "secs": round(secs, 3)}
    finally:
        silent.close()
    _record("unreachable_mcp", **observed)
    print(json.dumps(observed, sort_keys=True))
    for outcome in observed.values():          # no verdict exists in any of them
        assert outcome["http"] is None and outcome["exception"]


def test_unreachable_server_what_the_claude_code_hook_answers(tmp_path):
    """The same outage seen by the hook (the other way an agent is protected):
    the bare hook, exactly as Claude Code runs it, with its server a dead port."""
    env = {"HOME": str(tmp_path), "USERPROFILE": str(tmp_path), "PATH": os.environ.get("PATH", ""),
           "SYSTEMROOT": os.environ.get("SYSTEMROOT", ""), "STILLRUNNING_CVE_CHECK": "0",
           "STILLRUNNING_API_BASE": "http://127.0.0.1:%d" % _dead_port()}
    observed = {}
    for label, command in (("listed_package", "pip install beautifusoup"),
                           ("popular_package", "pip install requests")):
        event = json.dumps({"tool_name": "Bash", "tool_input": {"command": command}, "cwd": str(tmp_path)})
        start = time.monotonic()
        proc = subprocess.run([sys.executable, "-I", "-S", HOOK], input=event.encode("utf-8"),
                              capture_output=True, env=env, timeout=60)
        secs = time.monotonic() - start
        decision = "allow"
        if proc.stdout.strip():
            decision = json.loads(proc.stdout).get("hookSpecificOutput", {}).get("permissionDecision", "allow")
        if proc.returncode == 2:
            decision = "deny"
        observed[label] = {"exit": proc.returncode, "decision": decision, "secs": round(secs, 2),
                           "stderr": proc.stderr.decode("utf-8", "replace")[-200:]}
    _record("unreachable_hook", **observed)
    print(json.dumps(observed, sort_keys=True))
    for outcome in observed.values():
        assert outcome["exit"] in (0, 2)       # the hook itself never crashes or hangs here
