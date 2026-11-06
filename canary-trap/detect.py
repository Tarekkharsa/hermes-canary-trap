"""Find a canary credential in text, including the ways an injected instruction would disguise it.

A prompt injection that wants a secret out rarely asks for it verbatim; it asks the model to put it
in a URL, a header, a file, base64 it, hex it, reverse it or space it out. ``find`` checks text in
all of those forms and returns how the canary was hidden, or None.

Everything here is pure and deterministic; nothing is logged or stored.
"""

from __future__ import annotations

import base64
import binascii
import json
import re
import secrets
import string
from typing import Any, Iterable, Optional
from urllib.parse import unquote_plus

PREFIX = "hdk_live_"
_ALPHABET = string.ascii_lowercase + string.digits
CORE_LEN = 32
# A leak of any 16 consecutive characters of the core counts: an attacker may ask for "the first
# half of the key" or a truncated copy. 16 random [a-z0-9] chars = ~82 bits, so no accidental hits.
MIN_FRAGMENT = 16

_B64_RE = re.compile(r"[A-Za-z0-9+/_\-]{20,}={0,2}")
_HEX_RE = re.compile(r"(?:[0-9a-fA-F]{2}){12,}")
_ALNUM_RE = re.compile(r"[^a-z0-9]")


def new_canary() -> str:
    """A fresh decoy credential: ``hdk_live_`` + 32 random lowercase letters/digits."""
    return PREFIX + "".join(secrets.choice(_ALPHABET) for _ in range(CORE_LEN))


def core_of(canary: str) -> str:
    return canary[len(PREFIX):] if canary.startswith(PREFIX) else canary


def _alnum(text: str) -> str:
    return _ALNUM_RE.sub("", text.lower())


def _fragments(core: str) -> set[str]:
    return {core[i:i + MIN_FRAGMENT] for i in range(len(core) - MIN_FRAGMENT + 1)}


def _has(squashed: str, frags: set[str]) -> bool:
    if len(squashed) < MIN_FRAGMENT:
        return False
    for i in range(len(squashed) - MIN_FRAGMENT + 1):
        if squashed[i:i + MIN_FRAGMENT] in frags:
            return True
    return False


def _decoded_candidates(text: str) -> Iterable[tuple[str, str]]:
    for m in _B64_RE.finditer(text):
        chunk = m.group(0)
        for alt in (chunk, chunk.replace("-", "+").replace("_", "/")):
            try:
                raw = base64.b64decode(alt + "=" * (-len(alt) % 4), validate=False)
            except (binascii.Error, ValueError):
                continue
            yield "base64", raw.decode("utf-8", "ignore")
    for m in _HEX_RE.finditer(text):
        try:
            yield "hex", bytes.fromhex(m.group(0)).decode("utf-8", "ignore")
        except ValueError:
            continue


def find(text: str, canary: str) -> Optional[str]:
    """How ``canary`` appears in ``text`` ("plain", "url-encoded", "obfuscated", "reversed",
    "base64", "hex"), or None. Case, separators and partial copies (16+ chars) all count."""
    if not text or not canary:
        return None
    core = core_of(canary).lower()
    frags = _fragments(core)
    if canary.lower() in text.lower():
        return "plain"
    unq = unquote_plus(unquote_plus(text))
    if unq != text and core in unq.lower():
        return "url-encoded"
    squashed = _alnum(unq)
    if _has(squashed, frags):
        return "obfuscated"
    if _has(squashed[::-1], frags):
        return "reversed"
    for kind, decoded in _decoded_candidates(unq):
        d = _alnum(decoded)
        if _has(d, frags) or _has(d[::-1], frags):
            return kind
    return None


def strings_in(value: Any, limit: int = 2000) -> Iterable[str]:
    """Every string inside a tool's arguments (nested dicts/lists), plus their JSON form."""
    seen = 0
    stack = [value]
    while stack and seen < limit:
        v = stack.pop()
        seen += 1
        if isinstance(v, str):
            yield v
        elif isinstance(v, dict):
            stack.extend(v.keys())
            stack.extend(v.values())
        elif isinstance(v, (list, tuple, set)):
            stack.extend(v)
    try:
        yield json.dumps(value, ensure_ascii=False, default=str)
    except (TypeError, ValueError):
        pass


def find_in_args(args: Any, canary: str) -> Optional[str]:
    for s in strings_in(args):
        hit = find(s, canary)
        if hit:
            return hit
    return None


def redact(text: str, canary: str) -> str:
    return re.sub(re.escape(canary), "[canary redacted]", text, flags=re.IGNORECASE)
