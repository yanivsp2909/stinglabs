r"""The one function every exit where Sting SHOWS text passes it through.

Item C of fix/agents-block-and-env-reads (docs/110 §C).

⚠ TEXT THAT READS ONE WAY AND IS ANOTHER. A command, a path or a host can carry
characters a screen does not show as themselves:

    bidi controls        U+202A-U+202E, U+2066-U+2069, U+200E, U+200F, U+061C
                         (`invoice\u202etxt.exe` displays as `invoiceexe.txt`)
    zero-width           U+200B-U+200D, U+2060, U+FEFF (`ev\u200bil.invalid`
                         displays as `evil.invalid` and is another host)
    C0 / C1 controls     U+0000-U+001F, U+007F, U+0080-U+009F: an escape
                         sequence can move the cursor, clear a line, or recolour
                         what follows
    the rest of Unicode's format characters, the line and paragraph separators,
    variation selectors, the combining grapheme joiner, Hangul fillers and the
    tag block, which models read as hidden ASCII (the reviews)

Wherever Sting quotes such text to a person or to the model — the reason and
the sentence an agent reads (`adapters/_common`), the hook's own notes
(`hook_entry.run`), every string it ships (`shipper/mask.mask_record`: the panel
shows them), the installer's output (`install.say`) and the allow-once listing
(`tools/allow_once._clip`) — each such character is written as a visible
`\uXXXX` (`\UXXXXXXXX` above U+FFFF). A newline stays a newline in a message
of several lines.

⚠ ONLY WHAT IS SHOWN. Local records keep the raw bytes: they are evidence, the
hash chain covers them as written, and the engine decides on them as written.
This is a rendering, never a decision input.

Written with escapes throughout, so this file hides nothing either.
"""
from __future__ import annotations

import re

# Unicode 15's format characters (category Cf) in full, the C0/C1 controls with
# DEL, U+2028-2029, the variation selectors (FE00-FE0F, E0100-E01EF, and
# Mongolian's 180B-180D, 180F), U+034F, the Hangul fillers (115F, 1160, 3164,
# FFA0), the Khmer inherent vowels (17B4-17B5), the braille blank (2800) and
# the object replacement character (FFFC). The tag block E0000-E007F is taken
# whole.
_HIDDEN = ("\u0000-\u0009\u000b-\u001f\u007f-\u009f\u00ad\u034f"
           "\u0600-\u0605\u061c\u06dd\u070f\u0890-\u0891\u08e2"
           "\u115f-\u1160\u17b4-\u17b5\u180b-\u180f\u200b-\u200f"
           "\u2028-\u202e\u2060-\u2064\u2066-\u206f\u2800\u3164"
           "\ufe00-\ufe0f\ufeff\uffa0\ufff9-\ufffc\U000110bd\U000110cd"
           "\U00013430-\U0001343f\U0001bca0-\U0001bca3"
           "\U0001d173-\U0001d17a\U000e0000-\U000e007f"
           "\U000e0100-\U000e01ef")
_ONE_LINE = re.compile(f"[{_HIDDEN}\n]")
_LINES = re.compile(f"[{_HIDDEN}]")


def _code(match: re.Match) -> str:
    r"""`\uXXXX`, or `\UXXXXXXXX` above U+FFFF, so the code is unambiguous."""
    point = ord(match.group())
    return f"\\u{point:04X}" if point <= 0xFFFF else f"\\U{point:08X}"


def visible(text, *, multiline: bool = False):
    """`text` with every character in `_HIDDEN` written as its code; a newline
    kept when `multiline`. Anything that is not a string is returned as is."""
    if not isinstance(text, str):
        return text
    return (_LINES if multiline else _ONE_LINE).sub(_code, text)
