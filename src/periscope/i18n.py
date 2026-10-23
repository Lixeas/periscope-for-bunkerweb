"""Minimal internationalisation (stdlib only, no compile step).

English is the source language: msgids are English sentences used directly in the code and the
templates. French lives in `periscope.locales.fr.CATALOG` (msgid -> translation, named
`{placeholders}`). An unknown msgid, or the language "en", yields the msgid itself.
"""
from __future__ import annotations

import json
from collections.abc import Iterable

from markupsafe import Markup, escape

from periscope.locales.fr import CATALOG as _FR

SUPPORTED = ("en", "fr")
DEFAULT = "en"
COOKIE = "periscope_lang"
COOKIE_MAX_AGE = 365 * 24 * 3600
_CATALOGS = {"fr": _FR}


def N_(msgid: str) -> str:
    """Mark a msgid for extraction without translating it (module-level constants)."""
    return msgid


def normalize(value) -> str | None:
    """A supported language code, or None (anything else is ignored)."""
    if isinstance(value, str):
        v = value.strip().lower()
        if v in SUPPORTED:
            return v
    return None


def _lookup(lang: str, msgid: str) -> str:
    return _CATALOGS.get(lang, {}).get(msgid, msgid)


def _safe_format(text: str, params: dict) -> str:
    if not params:
        return text
    try:
        return text.format(**params)
    except (KeyError, IndexError, ValueError, AttributeError, TypeError):
        return text


def translate(lang: str | None, msgid: str, **params) -> str:
    """Translate `msgid` into `lang`; never raises (a bad or missing parameter leaves the text unformatted)."""
    text = _lookup(lang or DEFAULT, msgid)
    if not params:
        return text
    for candidate in (text, msgid):  # a broken translation falls back to the English text
        try:
            return candidate.format(**params)
        except (KeyError, IndexError, ValueError, AttributeError, TypeError):
            continue
    return text


def translate_html(lang: str | None, msgid: str, **params) -> Markup:
    """Template variant: the text is escaped, the parameters too (unless already Markup)."""
    text = escape(_lookup(lang or DEFAULT, msgid))
    try:
        return text.format(**params) if params else text
    except (KeyError, IndexError, ValueError, AttributeError, TypeError):
        return text


class LocalizedError(ValueError):
    """Validation error whose message is translated at display time (`str(e)` stays English)."""

    def __init__(self, msgid: str, **params):
        self.msgid, self.params = msgid, params
        super().__init__(_safe_format(msgid, params))

    def localize(self, lang: str | None) -> str:
        return translate(lang, self.msgid, **self.params)


def localize(lang: str | None, exc: BaseException) -> str:
    return exc.localize(lang) if isinstance(exc, LocalizedError) else str(exc)


# --- language-neutral storage of messages persisted in the database -----------------------

def _plain(v):
    if isinstance(v, str | int | float | bool) or v is None:
        return v
    if isinstance(v, dict) and ("m" in v or "l" in v):
        return v
    return str(v)


def pack_data(msgid: str, **params) -> dict:
    return {"m": msgid, "p": {k: _plain(v) for k, v in params.items()}}


def pack(msgid: str, **params) -> str:
    """Language-neutral stored form of a message: a JSON string {"m": msgid, "p": {...}}.
    A parameter may itself be a packed message (dict); it is translated recursively."""
    return json.dumps(pack_data(msgid, **params), ensure_ascii=False, separators=(",", ":"))


def pack_many(items: Iterable[str]) -> str:
    """Stored form of several packed messages, displayed joined by "; "."""
    parts = []
    for it in items:
        try:
            parts.append(json.loads(it))
        except ValueError:
            parts.append(it)
    return json.dumps({"l": parts}, ensure_ascii=False, separators=(",", ":"))


def _render_data(lang: str | None, data) -> str:
    if isinstance(data, dict) and isinstance(data.get("l"), list):
        return "; ".join(_render_data(lang, d) for d in data["l"])
    if isinstance(data, dict) and isinstance(data.get("m"), str):
        raw = data.get("p")
        params = {k: (_render_data(lang, v) if isinstance(v, dict) else v)
                  for k, v in (raw if isinstance(raw, dict) else {}).items()}
        return translate(lang, data["m"], **params)
    return data if isinstance(data, str) else str(data)


def render(lang: str | None, stored: str | None) -> str:
    """Display a stored message: packed JSON is translated, anything else (legacy rows) is shown as is."""
    if not stored:
        return ""
    if stored[:1] == "{":
        try:
            data = json.loads(stored)
        except ValueError:
            return stored
        if isinstance(data, dict) and ("m" in data or "l" in data):
            return _render_data(lang, data)
    return stored


# --- request language ---------------------------------------------------------------------

def parse_accept_language(header: str | None) -> str | None:
    """Best supported language of an Accept-Language header (q-values, primary subtags), or None."""
    best, best_q = None, 0.0
    for part in (header or "").split(","):
        tag, _, rest = part.strip().partition(";")
        q = 1.0
        rest = rest.strip()
        if rest.startswith("q="):
            try:
                q = float(rest[2:])
            except ValueError:
                continue
        lang = normalize(tag.strip().split("-")[0])
        if lang and q > best_q:
            best, best_q = lang, q
    return best


def lang_for(request) -> str:
    """Saved user preference > cookie > Accept-Language > default."""
    return (normalize(getattr(request.state, "lang_pref", None))
            or normalize(request.cookies.get(COOKIE))
            or parse_accept_language(request.headers.get("accept-language"))
            or DEFAULT)


def tr(request, msgid: str, **params) -> str:
    return translate(lang_for(request), msgid, **params)


def safe_next(value, default: str = "/") -> str:
    """A local path only (open-redirect safe): starts with a single '/', no backslash or control char."""
    if (isinstance(value, str) and 0 < len(value) <= 2048 and value[0] == "/"
            and not value.startswith("//") and "\\" not in value
            and all(32 <= ord(ch) != 127 for ch in value)):
        return value
    return default
