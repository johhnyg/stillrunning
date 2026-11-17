"""What is actually protecting this machine right now.

One report used by `stillrunning status`, `--doctor` and the end of `--setup`.
A layer is ON only when it was verified on disk — never because an install
command once printed "installed". Stdlib only, no network.
"""
import os
import shutil
import site

from . import claude_hook

PTH_NAME = "stillrunning-hook.pth"     # the one name --install-hook writes and status looks for
ON, OFF, NOT_VERIFIED = "ON", "OFF", "NOT VERIFIED"


def pth_path():
    """Where the import-hook .pth file is installed, or None."""
    candidates = []
    try:
        candidates += list(site.getsitepackages())
    except AttributeError:  # lint: allowed-silent(some virtualenvs have no getsitepackages → user site only)
        candidates = []
    try:
        candidates.append(site.getusersitepackages())
    except AttributeError:  # lint: allowed-silent(no user site → nothing more to search)
        candidates = candidates
    for directory in candidates:
        path = os.path.join(directory, PTH_NAME)
        if os.path.exists(path):
            return path
    return None


def _same_dir(a, b):
    try:
        return os.path.samefile(a, b)
    except OSError:
        return False


def protection_layers():
    """→ [{"key", "name", "state", "reason", "next", "install_time"}]"""
    layers = []
    home = os.path.expanduser("~")

    state, reason = claude_hook.verify_install()
    layers.append({
        "key": "claude_hook", "install_time": True,
        "name": "Claude Code hook (installs that Claude Code runs)",
        "state": {"on": ON, "off": OFF, "not_verified": NOT_VERIFIED}[state],
        "reason": reason,
        "next": None if state == "on" else "stillrunning --hook-claude-code"})

    bin_dir = os.path.join(home, ".stillrunning", "bin")
    wrapper = os.path.join(bin_dir, "pip")
    if not os.path.exists(wrapper):
        wrappers = (OFF, "not installed", "stillrunning shell-install")
    else:
        found = shutil.which("pip")
        if found and _same_dir(os.path.dirname(found), bin_dir):
            wrappers = (ON, "this shell runs pip and npm through the wrappers", None)
        elif os.environ.get("STILLRUNNING_SHELL_ACTIVE") == "1":
            # activate.sh was sourced: pip / npm are shell functions that call
            # the wrappers, even when a virtual environment is first on PATH.
            wrappers = (ON, "this shell runs pip and npm through the wrappers "
                            "(shell functions; a virtual environment is first on PATH)", None)
        else:
            wrappers = (NOT_VERIFIED, "installed, but this shell is not using them yet",
                        "open a new terminal, or run: source ~/.stillrunning/activate.sh")
    layers.append({"key": "shell_wrappers", "install_time": True,
                   "name": "Terminal wrappers (pip / npm typed in a shell)",
                   "state": wrappers[0], "reason": wrappers[1], "next": wrappers[2]})

    token, source = claude_hook.resolve_token()
    pth = pth_path()
    if not pth:
        imports = (OFF, "not installed (optional)", "stillrunning --install-hook")
    elif not token:
        imports = (OFF, "installed, but import-time checks only run with an API token",
                   "get a token at https://stillrunning.io and put it in "
                   "~/.stillrunning/config.json")
    else:
        imports = (ON, f"installed ({pth})", None)
    layers.append({"key": "import_hook", "install_time": False,
                   "name": "Import-time checks (optional, needs a token)",
                   "state": imports[0], "reason": imports[1], "next": imports[2]})

    layers.append({
        "key": "token", "install_time": False, "name": "API token",
        "state": ON if token else OFF,
        "reason": (f"found in {source}" if token else
                   "none — using the anonymous free tier, which allows a limited number of "
                   "lookups per day; after that each install asks you first"),
        "next": None if token else "optional: https://stillrunning.io/pricing"})
    return layers


def install_time_protection(layers):
    """True when at least one layer that checks installs is verified ON."""
    return any(layer["install_time"] and layer["state"] == ON for layer in layers)


def render(layers):
    lines = []
    for layer in layers:
        lines.append(f"[{layer['state']}] {layer['name']}")
        lines.append(f"      {layer['reason']}")
        if layer["next"]:
            lines.append(f"      next step: {layer['next']}")
    lines.append("")
    if install_time_protection(layers):
        lines.append("Installs are being looked up against the blocklist (a list of packages "
                     "reported as malicious) by the layers marked ON.")
    else:
        lines.append("NOT PROTECTED YET: no layer that checks installs is ON, so nothing is "
                     "looking up the packages you install.")
        lines.append("Fix it with one command:  stillrunning --hook-claude-code   (for Claude Code)")
        lines.append("                     or:  stillrunning shell-install        (for your terminal)")
    return "\n".join(lines)
