"""Output that never crashes on a console that cannot encode it.

On Windows, output that is piped or redirected (CI logs, PowerShell capturing
a command, ``> file``) is encoded with the ANSI code page (e.g. cp1252), which
has no ✓ ✗ ⚠ 🚨 ✅. A plain ``print`` of those raises UnicodeEncodeError —
a BLOCKED result became a traceback and the install interceptor failed for
every package. Entry points call ``make_output_safe()`` first: streams that are
already UTF-8 are left alone; any other stream keeps its encoding but writes
the symbols as ASCII words instead of failing. A character with no ASCII word
is written as a code-point tag, ``<U+0435>`` (never silently transliterated, so
a look-alike package name such as Cyrillic "rеquests" stays visibly different
from "requests"); an undecodable filename byte (surrogate escape) as ``<0xFF>``.

Only entry points call it (never at import): this package is imported into
other programs through sitecustomize, and their streams are not ours to change.
"""
import codecs
import sys

ERROR_HANDLER = "stillrunning-ascii"

# Symbols the CLI prints, spelled out for consoles that cannot show them.
_ASCII = {
    "✓": "OK",     # ✓
    "✔": "OK",     # ✔
    "✅": "OK",     # ✅
    "✗": "X",      # ✗
    "✘": "X",      # ✘
    "❌": "X",      # ❌
    "⚠": "!",      # ⚠
    "️": "",       # emoji variation selector
    "\U0001f6a8": "!!",  # 🚨
    "•": "*",      # •
    "·": "*",      # ·
    "—": "--",     # —
    "–": "-",      # –
    "→": "->",     # →
    "…": "...",    # …
}


def _ascii_tag(ch):
    code = ord(ch)
    if 0xDC80 <= code <= 0xDCFF:            # surrogateescape: an undecodable byte
        return f"<0x{code - 0xDC00:02X}>"
    return f"<U+{code:04X}>"


def _ascii_fallback(err):
    if not isinstance(err, UnicodeEncodeError):
        raise err
    chunk = err.object[err.start:err.end]
    return "".join(_ASCII[ch] if ch in _ASCII else _ascii_tag(ch) for ch in chunk), err.end


def _register():
    try:
        codecs.lookup_error(ERROR_HANDLER)
    except LookupError:
        codecs.register_error(ERROR_HANDLER, _ascii_fallback)


def _is_utf8(encoding):
    try:
        return codecs.lookup(encoding or "").name in ("utf-8", "utf-8-sig")
    except LookupError:
        return False


def make_output_safe(streams=None):
    """Make stdout/stderr unable to raise UnicodeEncodeError. Returns the names
    of the streams that were changed (for tests)."""
    _register()
    changed = []
    for name in (streams or ("stdout", "stderr")):
        stream = getattr(sys, name, None)
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is None or _is_utf8(getattr(stream, "encoding", None)):
            continue
        try:
            reconfigure(errors=ERROR_HANDLER)
            changed.append(name)
        except (ValueError, OSError, AttributeError) as exc:
            # a stream that cannot be reconfigured keeps its old behaviour
            sys.__stderr__ and sys.__stderr__.write(
                f"stillrunning: output encoding not adjusted ({type(exc).__name__})\n")
    return changed
