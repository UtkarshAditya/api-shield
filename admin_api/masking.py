"""Masks secrets and personal data in free text (scan evidence) before it is stored or returned.
Scanner evidence holds snippets of real responses, so it gets masked again at this boundary
even if the scanner already tried."""
from __future__ import annotations

import re

MASK = "••••"

_PATTERNS = [
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?(?:-----END [A-Z ]*PRIVATE KEY-----|$)", re.S),
    re.compile(r"\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*"),   # JWT
    re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/-]+=*"),
    re.compile(r"\b(?:sk|pk|rk)_(?:live|test)_[A-Za-z0-9]{8,}\b"),               # Stripe-style keys
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),                                         # AWS access key id
    re.compile(r"\b(?:ghp|gho|ghs|github_pat)_[A-Za-z0-9_]{16,}\b"),
    re.compile(r"(?i)\b(?:api|secret|access)[-_]?key[-_][A-Za-z0-9]{12,}\b"),
    re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"),               # email
    re.compile(r"\b(?:\d[ -]?){12,18}\d\b"),                                     # card-like numbers
    re.compile(r"\b(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}\b"),  # IPv4
]

DEFAULT_SENSITIVE_FIELDS = ("password", "passwd", "secret", "token", "api_key", "apikey",
                            "authorization", "access_token", "refresh_token", "ssn",
                            "card_number", "email")


def _field_pattern(fields) -> re.Pattern:
    names = "|".join(re.escape(f) for f in sorted(set(fields), key=len, reverse=True))
    # "password": "x"   password=x   'token': 'x'
    return re.compile(rf"""(?i)(["']?(?:{names})["']?\s*[:=]\s*)(?:"[^"]*"|'[^']*'|[^\s,;&}}]+)""")


def mask_text(text: str, fields=DEFAULT_SENSITIVE_FIELDS) -> str:
    if not text:
        return text
    out = text
    for pattern in _PATTERNS:  # tokens first, so "Authorization: Bearer <jwt>" loses the whole token
        out = pattern.sub(MASK, out)
    return _field_pattern(fields).sub(lambda m: m.group(1) + f'"{MASK}"', out)


def mask_value(value, fields=DEFAULT_SENSITIVE_FIELDS):
    """Recursively mask strings inside dicts and lists. Values under sensitive keys are
    replaced outright."""
    lowered = {f.lower() for f in fields}
    if isinstance(value, str):
        return mask_text(value, fields)
    if isinstance(value, dict):
        return {k: (MASK if str(k).lower() in lowered and v not in (None, "")
                    else mask_value(v, fields)) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [mask_value(v, fields) for v in value]
    return value


# Not after "{" or "/": "/users/{user_id}" is a path template, not a caller.
_CALLER_TOKEN = re.compile(r"(?<![{/\w])(ip|user)_([^\s,;\"'(){}<>]+)")
_PSEUDONYM = re.compile(r"[0-9a-f]{8}")


def pseudonymize_text(text: str, salt: str) -> str:
    """Replaces raw `ip_<addr>` / `user_<sub>` tokens in free text with their pseudonyms.
    Tokens that already are pseudonyms (8 hex chars) are left alone."""
    from .privacy import pseudonymize

    def repl(m: re.Match) -> str:
        return m.group(0) if _PSEUDONYM.fullmatch(m.group(2)) else pseudonymize(m.group(0), salt)
    return _CALLER_TOKEN.sub(repl, text or "")


def safe_caller(value: str, salt: str) -> str:
    """A caller id fit for the browser: pseudonyms and key hashes pass, raw values get hashed."""
    from .privacy import pseudonymize
    prefix, _, rest = (value or "").partition("_")
    if prefix in ("ip", "user", "key") and _PSEUDONYM.fullmatch(rest):
        return value
    return pseudonymize(value, salt)
