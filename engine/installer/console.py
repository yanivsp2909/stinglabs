"""Make this process's output survive the console it was launched from.

────────────────────────────────────────────────────────────────────────────────
⚠ WHAT ACTUALLY BREAKS, MEASURED, AND IT IS NOT THE DENY PATH
────────────────────────────────────────────────────────────────────────────────

`⚠` is in nearly every comment and installer line, and `cp1252` cannot encode
it. The fear was that a DENY carrying it would raise while the guard was
refusing something. **It cannot, and the reason is structural:**

    every adapter's `render()` builds its response with `json.dumps`, whose
    default `ensure_ascii=True` escapes non-ASCII to `\\uXXXX`

Measured across all five adapters with a Thai string and an arrow in the reason:
**pure ASCII out, cp1252-encodable, every time.** So the hook's stdout is safe on
any console encoding, and no verdict has ever been lost to this.

What DOES raise is the human-facing tooling, measured with
`PYTHONIOENCODING=cp1252`:

    install.py --status      UnicodeEncodeError, mid-output, after "Installed"
    tools/preflight.py       UnicodeEncodeError
    tools/windows_report.py  UnicodeEncodeError (died printing its own ⚠)

────────────────────────────────────────────────────────────────────────────────
⚠ THE FIX IS THE STREAM, AND "REPLACE" ALONE WOULD HAVE BEEN THE WRONG ONE
────────────────────────────────────────────────────────────────────────────────

Removing the character was rejected: it is hundreds of strings, it loses a
marker this codebase uses deliberately, and the next non-ASCII character
reintroduces the bug — the same run also showed a Thai `ร` failing in a fixture.

But reconfiguring stdout to UTF-8 **alone** is not a fix either, and this is the
trade the brief warns about: writing UTF-8 bytes at a console whose output
codepage is still 1252 renders `â\\x9a\\xa0` — **mojibake, in the text a customer
reads when the product does its job.** A crash replaced by garbage is not an
improvement.

So, in order:

    1 · ask Windows to make the console UTF-8 (`SetConsoleOutputCP(65001)`).
        On Windows Terminal and PowerShell 7 — the default on Windows 11 — this
        succeeds and `⚠` renders as `⚠`.
    2 · reconfigure the Python stream to match what the console now is.
    3 · and set `errors="replace"` REGARDLESS, so a console that refused step 1
        (an old conhost, a redirected pipe, a locale that is not cp1252 at all)
        prints `?` instead of raising.

⚠ **Step 3 is the one that must never be skipped.** Steps 1 and 2 are best-effort
cosmetics; step 3 is the guarantee. A tool that crashes while telling a developer
what is wrong with their install is worse than one that prints a `?`.
"""
from __future__ import annotations

import sys

UTF8_CODEPAGE = 65001


def _try_windows_utf8_console() -> bool:
    """Ask the console itself to become UTF-8. True if it did.

    ⚠ THIS IS THE STEP THAT AVOIDS MOJIBAKE, and it is the only one that can:
    Python's `reconfigure` changes how bytes are ENCODED, not how the console
    DECODES them. Without it, UTF-8 bytes at a cp1252 console are garbage.
    """
    if sys.platform != "win32":                                  # pragma: no cover
        return False
    try:                                                         # pragma: no cover
        import ctypes
        kernel32 = ctypes.windll.kernel32
        return bool(kernel32.SetConsoleOutputCP(UTF8_CODEPAGE))
    except Exception:                                            # noqa: BLE001
        # No console (output redirected), no ctypes, an unusual host. Not an
        # error: step 3 below still makes the write safe.
        return False


def make_output_safe() -> str:
    """Call once, at the top of any tool that prints for a human.

    Returns a short description of what it did, for `--status` output and bug
    reports — "which encoding am I on" must not be a guess.

    ⚠ NEVER RAISES. It is called before the tool has printed anything, so an
    exception here would be a crash with no output at all — strictly worse than
    the encoding problem it exists to fix.
    """
    console_utf8 = _try_windows_utf8_console()
    encoding = "utf-8" if console_utf8 or sys.platform != "win32" else None
    what = []
    for stream in (sys.stdout, sys.stderr):
        try:
            # `errors="replace"` on BOTH paths. This is the guarantee; the
            # encoding is the cosmetics.
            if encoding:
                stream.reconfigure(encoding=encoding, errors="replace")
            else:
                stream.reconfigure(errors="replace")
        except Exception:                                        # noqa: BLE001
            # A stream that is not reconfigurable (already wrapped, a pytest
            # capture object). Leave it; the tool still runs.
            pass
    what.append("console=utf-8" if console_utf8 else f"console={sys.stdout.encoding}")
    what.append(f"errors={getattr(sys.stdout, 'errors', '?')}")
    return " ".join(what)
