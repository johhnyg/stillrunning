#!/usr/bin/env python3
"""
stillrunning_scan.py - Static analysis security scanner for Python files and pickles.
Layer 1 analysis only - no code execution.

Usage: python3 stillrunning_scan.py <file>
"""

import ast
import sys
import os
import math
import struct
import pickle
import pickletools
from collections import defaultdict

# ─── Constants ───────────────────────────────────────────────────────────────

DANGEROUS_IMPORTS = {
    # Code execution
    "os.system", "subprocess", "eval", "exec", "__import__",
    # Network
    "socket", "urllib", "requests", "httpx",
    # Serialization (can execute code)
    "pickle", "marshal", "shelve",
    # Native code
    "ctypes", "cffi"
}

NETWORK_IMPORTS = {"socket", "urllib", "requests", "httpx"}

DANGEROUS_REDUCE_CALLS = {"os.system", "subprocess.call", "subprocess.run",
                          "subprocess.Popen", "eval", "exec", "os.popen"}

ENTROPY_THRESHOLD = 4.5
MIN_STRING_LENGTH = 20
MAX_HIGH_ENTROPY_SCORE = 60

# Scoring
SCORE_DANGEROUS_IMPORT = 30
SCORE_HIGH_ENTROPY = 20
SCORE_NETWORK_IMPORT = 15
SCORE_PKL_REDUCE_SYSTEM = 80
SCORE_EVAL_EXEC = 40

# Colors
RED = "\033[91m"
YELLOW = "\033[93m"
GREEN = "\033[92m"
CYAN = "\033[96m"
BOLD = "\033[1m"
RESET = "\033[0m"


# ─── Shannon Entropy ─────────────────────────────────────────────────────────

def shannon_entropy(data: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not data:
        return 0.0
    freq = defaultdict(int)
    for char in data:
        freq[char] += 1
    length = len(data)
    entropy = 0.0
    for count in freq.values():
        p = count / length
        if p > 0:
            entropy -= p * math.log2(p)
    return entropy


# ─── AST Analysis ────────────────────────────────────────────────────────────

class DangerousCodeVisitor(ast.NodeVisitor):
    """AST visitor that finds dangerous code patterns."""

    def __init__(self):
        self.findings = []
        self.imports = set()
        self.dangerous_imports = []
        self.network_imports = []
        self.eval_exec_calls = []
        self.high_entropy_strings = []

    def visit_Import(self, node):
        for alias in node.names:
            module = alias.name.split('.')[0]
            self.imports.add(module)
            if module in DANGEROUS_IMPORTS or alias.name in DANGEROUS_IMPORTS:
                self.dangerous_imports.append({
                    "line": node.lineno,
                    "import": alias.name,
                    "type": "network" if module in NETWORK_IMPORTS else "dangerous"
                })
        self.generic_visit(node)

    def visit_ImportFrom(self, node):
        if node.module:
            base_module = node.module.split('.')[0]
            self.imports.add(base_module)
            for alias in node.names:
                full_name = f"{node.module}.{alias.name}"
                if base_module in DANGEROUS_IMPORTS or full_name in DANGEROUS_IMPORTS:
                    self.dangerous_imports.append({
                        "line": node.lineno,
                        "import": full_name,
                        "type": "network" if base_module in NETWORK_IMPORTS else "dangerous"
                    })
        self.generic_visit(node)

    def visit_Call(self, node):
        # Check for eval() and exec() calls
        if isinstance(node.func, ast.Name):
            if node.func.id in ("eval", "exec"):
                self.eval_exec_calls.append({
                    "line": node.lineno,
                    "func": node.func.id
                })
        elif isinstance(node.func, ast.Attribute):
            # Check for os.system, subprocess.call, etc.
            if isinstance(node.func.value, ast.Name):
                full_name = f"{node.func.value.id}.{node.func.attr}"
                if full_name in DANGEROUS_IMPORTS:
                    self.dangerous_imports.append({
                        "line": node.lineno,
                        "import": full_name,
                        "type": "dangerous"
                    })
        self.generic_visit(node)

    def visit_Constant(self, node):
        # Check string literals for high entropy
        if isinstance(node.value, str) and len(node.value) >= MIN_STRING_LENGTH:
            entropy = shannon_entropy(node.value)
            if entropy >= ENTROPY_THRESHOLD:
                # Truncate for display
                preview = node.value[:50] + "..." if len(node.value) > 50 else node.value
                self.high_entropy_strings.append({
                    "line": node.lineno,
                    "entropy": entropy,
                    "preview": repr(preview),
                    "length": len(node.value)
                })
        self.generic_visit(node)

    # Python 3.7 compatibility
    def visit_Str(self, node):
        if len(node.s) >= MIN_STRING_LENGTH:
            entropy = shannon_entropy(node.s)
            if entropy >= ENTROPY_THRESHOLD:
                preview = node.s[:50] + "..." if len(node.s) > 50 else node.s
                self.high_entropy_strings.append({
                    "line": node.lineno,
                    "entropy": entropy,
                    "preview": repr(preview),
                    "length": len(node.s)
                })
        self.generic_visit(node)


def analyze_python_file(filepath: str) -> dict:
    """Analyze a Python file for dangerous patterns."""
    try:
        with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
            source = f.read()

        tree = ast.parse(source)
        visitor = DangerousCodeVisitor()
        visitor.visit(tree)

        return {
            "success": True,
            "dangerous_imports": visitor.dangerous_imports,
            "eval_exec_calls": visitor.eval_exec_calls,
            "high_entropy_strings": visitor.high_entropy_strings
        }
    except SyntaxError as e:
        return {"success": False, "error": f"Syntax error: {e}"}
    except Exception as e:
        return {"success": False, "error": str(e)}


# ─── Pickle Analysis ─────────────────────────────────────────────────────────

def analyze_pickle_file(filepath: str) -> dict:
    """Analyze a pickle file for dangerous __reduce__ calls WITHOUT executing."""
    findings = []

    try:
        with open(filepath, 'rb') as f:
            data = f.read()

        # Use pickletools to disassemble without executing
        # Look for REDUCE opcodes that call dangerous functions
        dangerous_reduces = []

        # Parse pickle opcodes
        ops = list(pickletools.genops(data))

        for i, (opcode, arg, pos) in enumerate(ops):
            # Look for GLOBAL opcode followed by REDUCE
            if opcode.name == 'GLOBAL':
                # arg is like "module\nname" or "module name"
                if arg:
                    parts = arg.replace('\n', ' ').split()
                    if len(parts) >= 2:
                        full_name = f"{parts[0]}.{parts[1]}"
                        # Check if this is a dangerous function
                        for dangerous in DANGEROUS_REDUCE_CALLS:
                            if dangerous in full_name or parts[1] in ("system", "popen", "call", "run", "Popen"):
                                dangerous_reduces.append({
                                    "position": pos,
                                    "call": full_name,
                                    "reason": "Dangerous function in pickle __reduce__"
                                })

            # Also check for STACK_GLOBAL (Python 3.8+)
            elif opcode.name == 'STACK_GLOBAL':
                # The module and name are on the stack - harder to analyze statically
                # Flag as suspicious
                findings.append({
                    "position": pos,
                    "warning": "STACK_GLOBAL opcode found - dynamic function resolution"
                })

        return {
            "success": True,
            "dangerous_reduces": dangerous_reduces,
            "warnings": findings
        }

    except Exception as e:
        return {"success": False, "error": str(e)}


# ─── Threat Score Calculation ────────────────────────────────────────────────

def calculate_threat_score(analysis: dict, is_pickle: bool = False) -> tuple[int, list]:
    """Calculate threat score and return (score, reasons)."""
    score = 0
    reasons = []

    if not analysis.get("success"):
        return 0, [f"Analysis failed: {analysis.get('error', 'unknown')}"]

    if is_pickle:
        # Pickle analysis
        for reduce in analysis.get("dangerous_reduces", []):
            score += SCORE_PKL_REDUCE_SYSTEM
            reasons.append(f"+{SCORE_PKL_REDUCE_SYSTEM}: __reduce__ calls {reduce['call']}")
        return score, reasons

    # Python file analysis

    # Dangerous imports
    for imp in analysis.get("dangerous_imports", []):
        if imp["type"] == "network":
            score += SCORE_NETWORK_IMPORT
            reasons.append(f"+{SCORE_NETWORK_IMPORT}: Network import '{imp['import']}' (line {imp['line']})")
        else:
            score += SCORE_DANGEROUS_IMPORT
            reasons.append(f"+{SCORE_DANGEROUS_IMPORT}: Dangerous import '{imp['import']}' (line {imp['line']})")

    # eval/exec calls
    for call in analysis.get("eval_exec_calls", []):
        score += SCORE_EVAL_EXEC
        reasons.append(f"+{SCORE_EVAL_EXEC}: {call['func']}() call (line {call['line']})")

    # High entropy strings (capped)
    entropy_score = 0
    for s in analysis.get("high_entropy_strings", []):
        if entropy_score < MAX_HIGH_ENTROPY_SCORE:
            entropy_score += SCORE_HIGH_ENTROPY
            reasons.append(f"+{SCORE_HIGH_ENTROPY}: High entropy string (E={s['entropy']:.2f}, len={s['length']}) line {s['line']}")
    score += min(entropy_score, MAX_HIGH_ENTROPY_SCORE)

    return score, reasons


# ─── Telegram Alert ──────────────────────────────────────────────────────────

def send_telegram_alert(filepath: str, score: int, reasons: list):
    """Send Telegram alert if score >= 20."""
    # Load credentials from .env - try server path first, fall back to customer install
    env_paths = [
        os.path.expanduser("~/my-app/.env"),
        os.path.expanduser("~/.stillrunning/.env"),
    ]
    bot_token = None
    chat_id = None

    for env_path in env_paths:
        if not os.path.exists(env_path):
            continue
        with open(env_path, 'r') as f:
            for line in f:
                line = line.strip()
                if line.startswith("TELEGRAM_BOT_TOKEN="):
                    bot_token = line.split("=", 1)[1].strip().strip('"').strip("'")
                elif line.startswith("TELEGRAM_CHAT_ID="):
                    chat_id = line.split("=", 1)[1].strip().strip('"').strip("'")
        if bot_token and chat_id:
            break

    if not bot_token or not chat_id:
        print(f"{YELLOW}[WARN]{RESET} Telegram credentials not found - skipping alert")
        return

    # Build message
    verdict = "DANGEROUS" if score >= 60 else "REVIEW"
    emoji = "\U0001F6A8" if score >= 60 else "\U000026A0"

    message = f"""{emoji} *StillRunning Scan Alert*

*File:* `{os.path.basename(filepath)}`
*Score:* {score} ({verdict})

*Findings:*
"""
    for r in reasons[:5]:  # Limit to 5 reasons
        message += f"- {r}\n"

    if len(reasons) > 5:
        message += f"_...and {len(reasons) - 5} more_\n"

    # Send via urllib (no external deps)
    import urllib.request
    import urllib.parse

    try:
        url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
        data = urllib.parse.urlencode({
            "chat_id": chat_id,
            "text": message,
            "parse_mode": "Markdown"
        }).encode()

        req = urllib.request.Request(url, data=data)
        with urllib.request.urlopen(req, timeout=10) as resp:
            if resp.status == 200:
                print(f"{GREEN}[OK]{RESET} Telegram alert sent")
            else:
                print(f"{YELLOW}[WARN]{RESET} Telegram returned status {resp.status}")
    except Exception as e:
        print(f"{YELLOW}[WARN]{RESET} Telegram alert failed: {e}")


# ─── Report Generation ───────────────────────────────────────────────────────

def print_report(filepath: str, score: int, reasons: list, analysis: dict):
    """Print colored terminal report."""
    print()
    print(f"{BOLD}{'='*60}{RESET}")
    print(f"{BOLD}STILLRUNNING SECURITY SCAN{RESET}")
    print(f"{'='*60}")
    print(f"File: {CYAN}{filepath}{RESET}")
    print()

    # Verdict
    if score < 20:
        verdict = f"{GREEN}{BOLD}CLEAN{RESET} {GREEN}\u2705{RESET}"
    elif score < 60:
        verdict = f"{YELLOW}{BOLD}REVIEW{RESET} {YELLOW}\u26A0{RESET}"
    else:
        verdict = f"{RED}{BOLD}DANGEROUS{RESET} {RED}\U0001F6A8 DO NOT RUN{RESET}"

    print(f"Threat Score: {BOLD}{score}{RESET}")
    print(f"Verdict: {verdict}")
    print()

    if reasons:
        print(f"{BOLD}Findings:{RESET}")
        for r in reasons:
            if "Dangerous" in r or "eval" in r or "exec" in r or "__reduce__" in r:
                print(f"  {RED}\u2022{RESET} {r}")
            elif "Network" in r:
                print(f"  {YELLOW}\u2022{RESET} {r}")
            elif "entropy" in r:
                print(f"  {CYAN}\u2022{RESET} {r}")
            else:
                print(f"  \u2022 {r}")
        print()

    # Details
    if analysis.get("high_entropy_strings"):
        print(f"{BOLD}High Entropy Strings (potential obfuscated payloads):{RESET}")
        for s in analysis["high_entropy_strings"][:3]:
            print(f"  Line {s['line']}: {s['preview']}")
        if len(analysis["high_entropy_strings"]) > 3:
            print(f"  ...and {len(analysis['high_entropy_strings']) - 3} more")
        print()

    print(f"{'='*60}")
    print()


# ─── Main ────────────────────────────────────────────────────────────────────

def main():
    if len(sys.argv) < 2:
        print(f"Usage: python3 {sys.argv[0]} <file>")
        print("Supported: .py, .pkl, .pickle files")
        sys.exit(1)

    filepath = sys.argv[1]

    if not os.path.exists(filepath):
        print(f"{RED}[ERROR]{RESET} File not found: {filepath}")
        sys.exit(1)

    # Determine file type
    ext = os.path.splitext(filepath)[1].lower()
    is_pickle = ext in (".pkl", ".pickle")

    if is_pickle:
        print(f"Analyzing pickle file: {filepath}")
        analysis = analyze_pickle_file(filepath)
    elif ext == ".py":
        print(f"Analyzing Python file: {filepath}")
        analysis = analyze_python_file(filepath)
    else:
        print(f"{YELLOW}[WARN]{RESET} Unknown file type: {ext}")
        print("Attempting Python analysis...")
        analysis = analyze_python_file(filepath)

    # Calculate score
    score, reasons = calculate_threat_score(analysis, is_pickle)

    # Print report
    print_report(filepath, score, reasons, analysis)

    # Send alert if score >= 20
    if score >= 20:
        send_telegram_alert(filepath, score, reasons)

    # Exit code based on verdict
    if score >= 60:
        sys.exit(2)  # DANGEROUS
    elif score >= 20:
        sys.exit(1)  # REVIEW
    else:
        sys.exit(0)  # CLEAN


if __name__ == "__main__":
    main()
