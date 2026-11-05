"""Best-effort credential redaction, shared by preview, rules and model prompts."""

import re
from urllib.parse import unquote_plus

MASK = "[REDACTED]"
SECRET = re.compile(
    r"(?:authorization|proxy.authorization|cookie|set.cookie|(?:x.)?api.?key|"
    r"access.?token|refresh.?token|token|password|passwd|secret|session(?:id)?)",
    re.I,
)


def sensitive(key: str) -> bool:
    return bool(SECRET.fullmatch(unquote_plus(key)))


def redact_object(value):
    if isinstance(value, dict):
        return {key: MASK if sensitive(key) else redact_object(item) for key, item in value.items()}
    if isinstance(value, list):
        return [redact_object(item) for item in value]
    return redact_text(value) if isinstance(value, str) else value


def redact_text(text: str) -> str:
    # Preserve newlines so source evidence retains its original line numbers.
    text = re.sub(
        r"(?im)^((?:authorization|proxy-authorization|cookie|set-cookie|x-api-key)\s*:)[^\r\n]*",
        lambda m: m[1] + " " + MASK,
        text,
    )
    text = re.sub(
        r"(?i)([\"']?(?:api[_-]?key|access[_-]?token|refresh[_-]?token|token|password|"
        r"passwd|secret|sessionid)[\"']?\s*[:=]\s*)([\"'])([^\r\n]*?)\2",
        lambda m: m[1] + m[2] + MASK + m[2],
        text,
    )
    text = re.sub(r"(?i)(\bBearer\s+)[A-Za-z0-9._~+/=-]+", lambda m: m[1] + MASK, text)
    text = re.sub(
        r"([^\s?&=]+)=([^&\s]*)",
        lambda m: m[1] + "=" + (MASK if sensitive(m[1]) else m[2]),
        text,
    )
    return text
