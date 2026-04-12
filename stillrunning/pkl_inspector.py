#!/usr/bin/env python3
"""
pkl-inspector: Static analysis for Python pickle files.
Detects malicious code without executing it.

Zero dependencies. Python 3.8+.

Usage:
    CLI: python3 pkl_inspector.py <file.pkl>
    API: from pkl_inspector import PklInspector; result = PklInspector().scan("file.pkl")

Copyright 2026 stillrunning.io
MIT License
"""

import io
import sys
import struct
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional, Tuple

__version__ = "0.1.0"


# ─── Pickle Opcodes (Protocol 0-5) ────────────────────────────────────────────
# We define these ourselves to avoid importing pickletools (which imports pickle)

OPCODES = {
    # Push constants
    0x4e: ("NONE", 0),
    0x88: ("NEWTRUE", 0),
    0x89: ("NEWFALSE", 0),
    0x49: ("INT", -1),      # -1 = newline terminated
    0x4c: ("LONG", -1),
    0x46: ("FLOAT", -1),
    0x47: ("BINFLOAT", 8),
    0x4a: ("BININT", 4),
    0x4b: ("BININT1", 1),
    0x4d: ("BININT2", 2),
    0x8a: ("LONG1", -2),    # -2 = 1-byte length prefix
    0x8b: ("LONG4", -3),    # -3 = 4-byte length prefix

    # Push strings
    0x53: ("STRING", -1),
    0x54: ("BINSTRING", -3),
    0x55: ("SHORT_BINSTRING", -2),
    0x56: ("UNICODE", -1),
    0x58: ("BINUNICODE", -3),
    0x8c: ("SHORT_BINUNICODE", -2),
    0x8d: ("BINUNICODE8", -4),  # -4 = 8-byte length prefix

    # Push bytes
    0x42: ("BINBYTES", -3),
    0x43: ("SHORT_BINBYTES", -2),
    0x8e: ("BINBYTES8", -4),
    0x96: ("BYTEARRAY8", -4),

    # Push collections
    0x5d: ("EMPTY_LIST", 0),
    0x5b: ("LIST", 0),
    0x61: ("APPEND", 0),
    0x65: ("APPENDS", 0),
    0x7d: ("EMPTY_DICT", 0),
    0x64: ("DICT", 0),
    0x73: ("SETITEM", 0),
    0x75: ("SETITEMS", 0),
    0x28: ("MARK", 0),
    0x74: ("TUPLE", 0),
    0x29: ("EMPTY_TUPLE", 0),
    0x85: ("TUPLE1", 0),
    0x86: ("TUPLE2", 0),
    0x87: ("TUPLE3", 0),
    0x8f: ("EMPTY_SET", 0),
    0x90: ("ADDITEMS", 0),
    0x91: ("FROZENSET", 0),

    # Stack manipulation
    0x30: ("POP", 0),
    0x31: ("POP_MARK", 0),
    0x32: ("DUP", 0),

    # Memo operations
    0x70: ("PUT", -1),
    0x71: ("BINPUT", 1),
    0x72: ("LONG_BINPUT", 4),
    0x67: ("GET", -1),
    0x68: ("BINGET", 1),
    0x6a: ("LONG_BINGET", 4),
    0x94: ("MEMOIZE", 0),

    # Object construction - THE DANGEROUS ONES
    0x63: ("GLOBAL", -5),     # -5 = two newline-terminated strings
    0x93: ("STACK_GLOBAL", 0),
    0x52: ("REDUCE", 0),      # Calls the callable!
    0x62: ("BUILD", 0),       # Calls __setstate__
    0x69: ("INST", -5),       # module\nname then MARK
    0x6f: ("OBJ", 0),
    0x81: ("NEWOBJ", 0),
    0x92: ("NEWOBJ_EX", 0),

    # Protocol
    0x80: ("PROTO", 1),
    0x95: ("FRAME", 8),

    # End
    0x2e: ("STOP", 0),

    # Extension registry
    0x82: ("EXT1", 1),
    0x83: ("EXT2", 2),
    0x84: ("EXT4", 4),

    # Persistent ID
    0x50: ("PERSID", -1),
    0x51: ("BINPERSID", 0),

    # Next buffer (protocol 5)
    0x97: ("NEXT_BUFFER", 0),
    0x98: ("READONLY_BUFFER", 0),
}


# ─── Threat Taxonomy ──────────────────────────────────────────────────────────

CRITICAL_CALLABLES = {
    # System execution - immediate code execution
    "os.system": 80,
    "os.popen": 80,
    "os.execl": 80,
    "os.execle": 80,
    "os.execlp": 80,
    "os.execlpe": 80,
    "os.execv": 80,
    "os.execve": 80,
    "os.execvp": 80,
    "os.execvpe": 80,
    "os.spawnl": 80,
    "os.spawnle": 80,
    "os.spawnlp": 80,
    "os.spawnlpe": 80,
    "os.spawnv": 80,
    "os.spawnve": 80,
    "os.spawnvp": 80,
    "os.spawnvpe": 80,
    "posix.system": 80,
    "nt.system": 80,

    # Subprocess - process spawning
    "subprocess.call": 70,
    "subprocess.run": 70,
    "subprocess.Popen": 70,
    "subprocess.check_call": 70,
    "subprocess.check_output": 70,
    "subprocess.getoutput": 70,
    "subprocess.getstatusoutput": 70,

    # eval/exec - code execution
    "builtins.eval": 90,
    "builtins.exec": 90,
    "builtins.compile": 85,
    "__builtin__.eval": 90,
    "__builtin__.exec": 90,
    "__builtin__.compile": 85,
}

HIGH_CALLABLES = {
    # File system write
    "builtins.open": 50,
    "__builtin__.open": 50,
    "io.open": 50,
    "_io.open": 50,
    "os.remove": 45,
    "os.unlink": 45,
    "os.rmdir": 45,
    "os.makedirs": 35,
    "shutil.rmtree": 55,
    "shutil.copy": 40,
    "shutil.copy2": 40,
    "shutil.move": 45,

    # Import manipulation
    "importlib.import_module": 50,
    "__import__": 50,
    "builtins.__import__": 50,
}

MEDIUM_CALLABLES = {
    # Network operations
    "socket.socket": 30,
    "urllib.request.urlopen": 35,
    "urllib.request.urlretrieve": 40,
    "http.client.HTTPConnection": 30,
    "http.client.HTTPSConnection": 30,

    # Code loading
    "types.FunctionType": 40,
    "types.CodeType": 45,
    "marshal.loads": 50,
}

# Obfuscation patterns
OBFUSCATION_SCORES = {
    "nested_reduce": 40,
    "lambda_function": 30,
    "base64_decode": 35,
    "codecs_decode": 30,
    "getattr_chain": 25,
    "unknown_callable": 20,
}

# Verdict thresholds
THRESHOLD_SUSPICIOUS = 1
THRESHOLD_DANGEROUS = 41
THRESHOLD_CRITICAL = 80


# ─── Opcode Parser ────────────────────────────────────────────────────────────

class PickleOpParser:
    """Parse pickle opcodes from raw bytes without executing."""

    def __init__(self, data: bytes):
        self.data = data
        self.pos = 0
        self.ops: List[Tuple[str, Any, int]] = []

    def _read(self, n: int) -> bytes:
        """Read n bytes from stream."""
        result = self.data[self.pos:self.pos + n]
        self.pos += n
        return result

    def _read_line(self) -> bytes:
        """Read until newline."""
        end = self.data.find(b'\n', self.pos)
        if end == -1:
            end = len(self.data)
        result = self.data[self.pos:end]
        self.pos = end + 1
        return result

    def _read_uint1(self) -> int:
        return self._read(1)[0]

    def _read_uint2(self) -> int:
        return struct.unpack('<H', self._read(2))[0]

    def _read_uint4(self) -> int:
        return struct.unpack('<I', self._read(4))[0]

    def _read_uint8(self) -> int:
        return struct.unpack('<Q', self._read(8))[0]

    def _read_int4(self) -> int:
        return struct.unpack('<i', self._read(4))[0]

    def parse(self) -> List[Tuple[str, Any, int]]:
        """Parse all opcodes and return list of (name, arg, position)."""
        self.pos = 0
        self.ops = []

        while self.pos < len(self.data):
            pos = self.pos
            try:
                opcode = self._read(1)[0]
            except IndexError:
                break

            if opcode not in OPCODES:
                # Unknown opcode - might be corrupted or newer protocol
                self.ops.append(("UNKNOWN", opcode, pos))
                continue

            name, arg_type = OPCODES[opcode]
            arg = None

            try:
                if arg_type == 0:
                    # No argument
                    pass
                elif arg_type == -1:
                    # Newline-terminated string
                    arg = self._read_line().decode('utf-8', errors='replace')
                elif arg_type == -2:
                    # 1-byte length prefixed
                    length = self._read_uint1()
                    arg = self._read(length)
                    if name.endswith("UNICODE"):
                        arg = arg.decode('utf-8', errors='replace')
                elif arg_type == -3:
                    # 4-byte length prefixed
                    length = self._read_uint4()
                    arg = self._read(length)
                    if name.endswith("UNICODE") or name == "BINSTRING":
                        arg = arg.decode('utf-8', errors='replace') if isinstance(arg, bytes) else arg
                elif arg_type == -4:
                    # 8-byte length prefixed
                    length = self._read_uint8()
                    arg = self._read(length)
                    if name.endswith("UNICODE"):
                        arg = arg.decode('utf-8', errors='replace')
                elif arg_type == -5:
                    # Two newline-terminated strings (GLOBAL, INST)
                    module = self._read_line().decode('utf-8', errors='replace')
                    name_part = self._read_line().decode('utf-8', errors='replace')
                    arg = (module, name_part)
                elif arg_type > 0:
                    # Fixed length bytes
                    arg = self._read(arg_type)
                    if arg_type == 1:
                        arg = arg[0]
                    elif arg_type == 2:
                        arg = struct.unpack('<H', arg)[0]
                    elif arg_type == 4:
                        arg = struct.unpack('<I', arg)[0]
                    elif arg_type == 8:
                        arg = struct.unpack('<d', arg)[0]
            except Exception:
                # Parsing error - record what we have
                pass

            self.ops.append((name, arg, pos))

            if name == "STOP":
                break

        return self.ops


# ─── Threat Analyzer ──────────────────────────────────────────────────────────

class ThreatAnalyzer:
    """Analyze parsed opcodes for malicious patterns."""

    def __init__(self, ops: List[Tuple[str, Any, int]]):
        self.ops = ops
        self.findings: List[Dict[str, Any]] = []
        self.score = 0
        self.globals_seen: List[Tuple[str, int]] = []  # (full_name, position)

    def _add_finding(self, finding_type: str, severity: str,
                     description: str, score_add: int, **kwargs):
        """Add a finding and increment score."""
        finding = {
            "type": finding_type,
            "severity": severity,
            "description": description,
            "score_contribution": score_add,
            **kwargs
        }
        self.findings.append(finding)
        self.score += score_add

    def analyze(self) -> Tuple[int, List[Dict[str, Any]]]:
        """Analyze opcodes and return (score, findings)."""
        self.findings = []
        self.score = 0
        self.globals_seen = []

        # Simulate the pickle stack to resolve STACK_GLOBAL
        stack: List[Any] = []
        mark_stack: List[int] = []  # Positions of marks
        memo: Dict[int, Any] = {}
        memo_counter = 0

        reduce_count = 0
        last_callable = None
        last_callable_pos = None

        for i, (name, arg, pos) in enumerate(self.ops):

            # Push string values onto stack
            if name in ("SHORT_BINUNICODE", "BINUNICODE", "UNICODE",
                       "STRING", "BINSTRING", "SHORT_BINSTRING",
                       "SHORT_BINBYTES", "BINBYTES", "BINBYTES8"):
                stack.append(arg)
                # Also check string content for suspicious patterns
                if isinstance(arg, str):
                    self._check_string_content(arg, pos)

            # Push numeric values
            elif name in ("INT", "BININT", "BININT1", "BININT2",
                         "LONG", "LONG1", "LONG4", "FLOAT", "BINFLOAT"):
                stack.append(arg)

            # Push constants
            elif name == "NONE":
                stack.append(None)
            elif name == "NEWTRUE":
                stack.append(True)
            elif name == "NEWFALSE":
                stack.append(False)

            # Collections
            elif name == "EMPTY_LIST":
                stack.append([])
            elif name == "EMPTY_DICT":
                stack.append({})
            elif name == "EMPTY_TUPLE":
                stack.append(())
            elif name == "EMPTY_SET":
                stack.append(set())

            # Mark for varargs
            elif name == "MARK":
                mark_stack.append(len(stack))

            # Tuple building
            elif name == "TUPLE":
                if mark_stack:
                    mark_pos = mark_stack.pop()
                    items = tuple(stack[mark_pos:])
                    stack = stack[:mark_pos]
                    stack.append(items)
            elif name == "TUPLE1":
                if stack:
                    stack.append((stack.pop(),))
            elif name == "TUPLE2":
                if len(stack) >= 2:
                    b, a = stack.pop(), stack.pop()
                    stack.append((a, b))
            elif name == "TUPLE3":
                if len(stack) >= 3:
                    c, b, a = stack.pop(), stack.pop(), stack.pop()
                    stack.append((a, b, c))

            # Memo operations
            elif name == "MEMOIZE":
                if stack:
                    memo[memo_counter] = stack[-1]
                    memo_counter += 1
            elif name in ("PUT", "BINPUT", "LONG_BINPUT"):
                if stack and arg is not None:
                    memo[arg] = stack[-1]
            elif name in ("GET", "BINGET", "LONG_BINGET"):
                if arg is not None and arg in memo:
                    stack.append(memo[arg])

            # GLOBAL - protocol 0-3 style (module\nname inline)
            elif name == "GLOBAL":
                if isinstance(arg, tuple) and len(arg) == 2:
                    module, attr = arg
                    full_name = f"{module}.{attr}"
                    self.globals_seen.append((full_name, pos))
                    stack.append(("CALLABLE", full_name))
                    last_callable = full_name
                    last_callable_pos = pos
                    self._check_callable(full_name, pos)

            # STACK_GLOBAL - protocol 4+ style (module and name from stack)
            elif name == "STACK_GLOBAL":
                if len(stack) >= 2:
                    attr = stack.pop()
                    module = stack.pop()
                    if isinstance(module, str) and isinstance(attr, str):
                        full_name = f"{module}.{attr}"
                        self.globals_seen.append((full_name, pos))
                        stack.append(("CALLABLE", full_name))
                        last_callable = full_name
                        last_callable_pos = pos
                        self._check_callable(full_name, pos)
                    else:
                        # Dynamic values, can't resolve statically
                        stack.append(("CALLABLE", "<dynamic>"))
                        self._add_finding(
                            "DYNAMIC_GLOBAL",
                            "MEDIUM",
                            "STACK_GLOBAL with non-string values - callable determined at runtime",
                            OBFUSCATION_SCORES["unknown_callable"],
                            position=pos
                        )
                else:
                    # Not enough values on stack
                    stack.append(("CALLABLE", "<unknown>"))

            # REDUCE - this is where execution happens
            elif name == "REDUCE":
                reduce_count += 1
                # Pop args and callable from stack
                args = stack.pop() if stack else None
                callable_info = stack.pop() if stack else None

                # Push placeholder result
                stack.append(("RESULT", reduce_count))

                # Check for nested reduces (obfuscation)
                if reduce_count > 1:
                    self._add_finding(
                        "NESTED_REDUCE",
                        "MEDIUM",
                        f"Multiple REDUCE opcodes ({reduce_count}) - potential obfuscation pattern",
                        OBFUSCATION_SCORES["nested_reduce"] if reduce_count == 2 else 10,
                        position=pos,
                        reduce_count=reduce_count
                    )

            # NEWOBJ - another way to call constructors
            elif name == "NEWOBJ":
                if len(stack) >= 2:
                    args = stack.pop()
                    cls = stack.pop()
                    stack.append(("INSTANCE", cls))

            # BUILD - calls __setstate__
            elif name == "BUILD":
                if len(stack) >= 2:
                    state = stack.pop()
                    obj = stack[-1] if stack else None

            # Stack manipulation
            elif name == "POP":
                if stack:
                    stack.pop()
            elif name == "POP_MARK":
                if mark_stack:
                    mark_pos = mark_stack.pop()
                    stack = stack[:mark_pos]
            elif name == "DUP":
                if stack:
                    stack.append(stack[-1])

            # List/dict building
            elif name == "APPEND":
                if len(stack) >= 2:
                    item = stack.pop()
                    # list is below
            elif name == "APPENDS":
                if mark_stack and stack:
                    mark_pos = mark_stack.pop()
                    items = stack[mark_pos:]
                    stack = stack[:mark_pos]
            elif name == "SETITEM":
                if len(stack) >= 3:
                    value = stack.pop()
                    key = stack.pop()
            elif name == "SETITEMS":
                if mark_stack:
                    mark_pos = mark_stack.pop()
                    stack = stack[:mark_pos]

        return self.score, self.findings

    def _check_callable(self, full_name: str, pos: int):
        """Check if a callable is in our threat taxonomy."""
        # Check critical
        if full_name in CRITICAL_CALLABLES:
            score = CRITICAL_CALLABLES[full_name]
            self._add_finding(
                "CRITICAL_CALLABLE_LOADED",
                "CRITICAL",
                f"Dangerous callable '{full_name}' loaded via GLOBAL opcode - will execute on REDUCE",
                score,
                callable=full_name,
                position=pos
            )
            return

        # Check high
        if full_name in HIGH_CALLABLES:
            score = HIGH_CALLABLES[full_name]
            self._add_finding(
                "HIGH_RISK_CALLABLE_LOADED",
                "HIGH",
                f"High-risk callable '{full_name}' loaded - may perform sensitive operations",
                score,
                callable=full_name,
                position=pos
            )
            return

        # Check medium
        if full_name in MEDIUM_CALLABLES:
            score = MEDIUM_CALLABLES[full_name]
            self._add_finding(
                "MEDIUM_RISK_CALLABLE_LOADED",
                "MEDIUM",
                f"Network/code callable '{full_name}' loaded - review required",
                score,
                callable=full_name,
                position=pos
            )
            return

        # Check for obfuscation patterns
        if "base64" in full_name.lower() and "decode" in full_name.lower():
            self._add_finding(
                "OBFUSCATION_PATTERN",
                "MEDIUM",
                f"Base64 decode function '{full_name}' - common payload obfuscation",
                OBFUSCATION_SCORES["base64_decode"],
                callable=full_name,
                position=pos
            )

        if "codecs" in full_name.lower() and "decode" in full_name.lower():
            self._add_finding(
                "OBFUSCATION_PATTERN",
                "MEDIUM",
                f"Codecs decode function '{full_name}' - potential obfuscation",
                OBFUSCATION_SCORES["codecs_decode"],
                callable=full_name,
                position=pos
            )

        if "getattr" in full_name.lower():
            self._add_finding(
                "OBFUSCATION_PATTERN",
                "LOW",
                f"getattr function '{full_name}' - can be used to evade static analysis",
                OBFUSCATION_SCORES["getattr_chain"],
                callable=full_name,
                position=pos
            )

    def _check_reduce_call(self, callable_name: str, global_pos: int, reduce_pos: int):
        """Check a GLOBAL+REDUCE pair for malicious patterns."""
        # Already checked in _check_callable, but we can add context here
        pass

    def _check_string_content(self, content: str, pos: int):
        """Check string content for suspicious patterns."""
        suspicious_patterns = [
            ("rm -rf", "DESTRUCTIVE_COMMAND"),
            ("curl ", "NETWORK_DOWNLOAD"),
            ("wget ", "NETWORK_DOWNLOAD"),
            ("/bin/sh", "SHELL_REFERENCE"),
            ("/bin/bash", "SHELL_REFERENCE"),
            ("powershell", "SHELL_REFERENCE"),
            (".ssh/", "CREDENTIAL_ACCESS"),
            ("id_rsa", "SSH_KEY_REFERENCE"),
            ("eval(", "EVAL_STRING"),
            ("exec(", "EXEC_STRING"),
            ("__import__", "DYNAMIC_IMPORT"),
        ]

        content_lower = content.lower()
        for pattern, pattern_type in suspicious_patterns:
            if pattern.lower() in content_lower:
                self._add_finding(
                    "SUSPICIOUS_STRING",
                    "LOW",
                    f"String contains suspicious pattern '{pattern}' - review context",
                    10,
                    pattern=pattern,
                    pattern_type=pattern_type,
                    position=pos,
                    preview=content[:100] if len(content) > 100 else content
                )
                break  # Only report first match per string


# ─── Main Inspector Class ─────────────────────────────────────────────────────

class PklInspector:
    """
    Static analysis for Python pickle files.
    Detects malicious code without executing it.
    """

    def __init__(self):
        self.last_result: Optional[Dict[str, Any]] = None

    def scan(self, filepath: str) -> Dict[str, Any]:
        """
        Scan a pickle file and return threat analysis.

        Returns:
            {
                "file": str,
                "score": int,
                "verdict": "CLEAN" | "SUSPICIOUS" | "DANGEROUS" | "CRITICAL",
                "findings": [...],
                "safe_to_load": bool,
                "analyzed_at": str (ISO timestamp),
                "version": str
            }
        """
        try:
            with open(filepath, 'rb') as f:
                data = f.read()
        except FileNotFoundError:
            return self._error_result(filepath, f"File not found: {filepath}")
        except PermissionError:
            return self._error_result(filepath, f"Permission denied: {filepath}")
        except Exception as e:
            return self._error_result(filepath, f"Error reading file: {e}")

        return self.scan_bytes(data, filepath)

    def scan_bytes(self, data: bytes, source: str = "<bytes>") -> Dict[str, Any]:
        """
        Scan pickle bytes and return threat analysis.
        """
        # Parse opcodes
        try:
            parser = PickleOpParser(data)
            ops = parser.parse()
        except Exception as e:
            return self._error_result(source, f"Failed to parse pickle: {e}")

        # Analyze for threats
        analyzer = ThreatAnalyzer(ops)
        score, findings = analyzer.analyze()

        # Determine verdict
        if score >= THRESHOLD_CRITICAL:
            verdict = "CRITICAL"
        elif score >= THRESHOLD_DANGEROUS:
            verdict = "DANGEROUS"
        elif score >= THRESHOLD_SUSPICIOUS:
            verdict = "SUSPICIOUS"
        else:
            verdict = "CLEAN"

        result = {
            "file": source,
            "score": score,
            "verdict": verdict,
            "findings": findings,
            "safe_to_load": score < THRESHOLD_DANGEROUS,
            "analyzed_at": datetime.now(timezone.utc).isoformat(),
            "version": __version__,
            "opcode_count": len(ops),
            "globals_found": [g[0] for g in analyzer.globals_seen]
        }

        self.last_result = result
        return result

    def _error_result(self, filepath: str, error: str) -> Dict[str, Any]:
        """Return an error result."""
        return {
            "file": filepath,
            "score": 0,
            "verdict": "ERROR",
            "findings": [{"type": "ERROR", "description": error}],
            "safe_to_load": False,
            "analyzed_at": datetime.now(timezone.utc).isoformat(),
            "version": __version__,
            "error": error
        }


# ─── CLI ──────────────────────────────────────────────────────────────────────

def _colorize(text: str, color: str) -> str:
    """Add ANSI color to text."""
    colors = {
        "red": "\033[91m",
        "green": "\033[92m",
        "yellow": "\033[93m",
        "cyan": "\033[96m",
        "bold": "\033[1m",
        "reset": "\033[0m"
    }
    return f"{colors.get(color, '')}{text}{colors['reset']}"


def _print_result(result: Dict[str, Any], verbose: bool = False):
    """Print scan result to terminal."""
    print()
    print("=" * 60)
    print(_colorize("PKL-INSPECTOR SCAN RESULT", "bold"))
    print("=" * 60)
    print(f"File: {_colorize(result['file'], 'cyan')}")
    print(f"Score: {_colorize(str(result['score']), 'bold')}")

    verdict = result["verdict"]
    if verdict == "CLEAN":
        print(f"Verdict: {_colorize('CLEAN', 'green')} - Safe to load")
    elif verdict == "SUSPICIOUS":
        print(f"Verdict: {_colorize('SUSPICIOUS', 'yellow')} - Review before loading")
    elif verdict == "DANGEROUS":
        print(f"Verdict: {_colorize('DANGEROUS', 'red')} - Do not load")
    elif verdict == "CRITICAL":
        print(f"Verdict: {_colorize('CRITICAL', 'red')} {_colorize('DO NOT LOAD', 'bold')}")
    else:
        print(f"Verdict: {verdict}")

    print()

    if result.get("findings"):
        print(_colorize("Findings:", "bold"))
        for f in result["findings"]:
            severity = f.get("severity", "INFO")
            if severity == "CRITICAL":
                marker = _colorize("[CRITICAL]", "red")
            elif severity == "HIGH":
                marker = _colorize("[HIGH]", "red")
            elif severity == "MEDIUM":
                marker = _colorize("[MEDIUM]", "yellow")
            else:
                marker = _colorize("[LOW]", "cyan")

            print(f"  {marker} {f.get('description', f.get('type', 'Unknown'))}")

            if verbose:
                if "callable" in f:
                    print(f"           Callable: {f['callable']}")
                if "position" in f:
                    print(f"           Position: byte {f['position']}")
                if "score_contribution" in f:
                    print(f"           Score: +{f['score_contribution']}")
        print()

    if result.get("globals_found"):
        print(f"Globals loaded: {', '.join(result['globals_found'][:10])}")
        if len(result.get("globals_found", [])) > 10:
            print(f"  ...and {len(result['globals_found']) - 10} more")
        print()

    print("=" * 60)
    print()


def main():
    """CLI entry point."""
    import argparse

    parser = argparse.ArgumentParser(
        description="pkl-inspector: Static analysis for Python pickle files"
    )
    parser.add_argument("file", help="Pickle file to analyze")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Show detailed findings")
    parser.add_argument("-j", "--json", action="store_true",
                        help="Output JSON instead of formatted text")
    parser.add_argument("--version", action="version",
                        version=f"pkl-inspector {__version__}")

    args = parser.parse_args()

    inspector = PklInspector()
    result = inspector.scan(args.file)

    if args.json:
        import json
        print(json.dumps(result, indent=2))
    else:
        _print_result(result, verbose=args.verbose)

    # Exit codes
    if result["verdict"] == "CRITICAL":
        sys.exit(3)
    elif result["verdict"] == "DANGEROUS":
        sys.exit(2)
    elif result["verdict"] == "SUSPICIOUS":
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == "__main__":
    main()
