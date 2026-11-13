"""Best-effort credential redaction shared by previews, rule evidence and model input.

Limits (documented, not hidden): this is heuristic. Secrets stored under innocuous names,
assembled across expressions, or encoded unusually can still pass. Masking leans towards
false positives on credential-like names, never changes line counts, and is applied to
string literals and comments only, so the structure of submitted code stays readable.

Every pattern here must stay linear in the input length: match starts are anchored to
token boundaries and quantifiers are bounded, and callers check input budgets first.
"""

import io
import re
import tokenize
from urllib.parse import unquote_plus

MASK = "[REDACTED]"
_SENSITIVE_PARTS = frozenset(
    {
        "auth", "authorization", "authtoken", "apikey", "bearer", "cookie", "credential",
        "jsessionid", "jwt", "passphrase", "passwd", "password", "phpsessid", "pwd", "secret",
        "sessid", "session", "sessionid", "sid", "signature", "token",
    }
)  # fmt: skip
_SENSITIVE_PAIRS = frozenset(
    {("api", "key"), ("access", "key"), ("private", "key"), ("secret", "key"), ("app", "key")}
)
_EXACT = frozenset({"key", "sig", "pass"})
_WORDS = re.compile(r"[A-Z]+(?![a-z])|[A-Z]?[a-z]+|\d+")
_PLACEHOLDER = re.compile(r"""['"]?(?:%[sdr]|\?|\{[^{}]{0,64}\}|:\w{1,64}|%\(\w{1,64}\)s)?['"]?""")

_KNOWN_SECRETS = [
    re.compile(
        r"-----BEGIN [A-Z ]{0,40}PRIVATE KEY-----.*?(?:-----END [A-Z ]{0,40}PRIVATE KEY-----|\Z)",
        re.S,
    ),
    re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,255}\b"),
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,255}\b"),
    re.compile(r"\b[sr]k_(?:live|test)_[A-Za-z0-9]{10,255}\b"),
    re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{16,255}"),
    re.compile(r"\bxox[abpors]-[A-Za-z0-9-]{10,255}"),
    re.compile(r"\beyJ[A-Za-z0-9_-]{8,4096}\.eyJ[A-Za-z0-9_-]{8,4096}\.[A-Za-z0-9_-]{0,4096}"),
]
# Bearer/Token credentials are masked even when purely alphabetic (prose such as
# "Token refreshed" may be over-masked; accepted cost). Basic is masked when the value has a
# base64 shape (length multiple of 4, or digits/+/=); Digest when a parameter list follows.
_BEARER = re.compile(r"(?i)\b(Bearer|Token)([ \t]+)[A-Za-z0-9._~+/=-]{8,4096}")
_BASIC = re.compile(r"(?i)\b(Basic)([ \t]+)([A-Za-z0-9+/]{6,4096}={0,2})(?![A-Za-z0-9+/=])")
_DIGEST = re.compile(r"(?i)\b(Digest)([ \t]+)(?=[A-Za-z_]{1,32}=)[^\n]{1,4096}")
_BASE64_HINT = re.compile(r"[0-9+/=]")
_USERINFO = re.compile(r"\b([a-zA-Z][a-zA-Z0-9+.-]{1,15}://[^/\s:@]{1,256}:)[^/\s@]{1,256}@")
_HEADER_LINE = re.compile(r"(?m)^([A-Za-z][A-Za-z0-9-]{0,63})([ \t]*:[ \t]*)([^\n]+)")
_QUOTED_ASSIGN = re.compile(
    r"""(?<![\w.-])(["']?)([A-Za-z_][\w.-]{0,63})\1([ \t]*[:=][ \t]*)([rRbBuUfF]{0,2})(["'])"""
    r"""([^\n]*?)(?<!\\)\5"""
)
_KEY_VALUE = re.compile(r"(?<![^\s?&;,(/])([A-Za-z0-9_.%\[\]-]{1,128})=(?!=)([^&;\s]*)")
_LOOSE = re.compile(r"""(?<![\w-])([A-Za-z_][\w-]{0,63})([ \t]*[:=][ \t]*)([^\s,;'"]{1,256})""")


def sensitive(key: str) -> bool:
    """Whether a field, header, variable or path name looks like it carries a credential."""
    name = key[:256]
    for _ in range(2):
        decoded = unquote_plus(name)
        if decoded == name:
            break
        name = decoded
    if name.lower() in _EXACT:
        return True
    parts = [part.lower() for part in _WORDS.findall(name)]
    if any({part, part.removesuffix("s")} & _SENSITIVE_PARTS for part in parts):
        return True
    return any(pair in _SENSITIVE_PAIRS for pair in zip(parts, parts[1:], strict=False))


def _is_placeholder(value: str) -> bool:
    return not value or bool(_PLACEHOLDER.fullmatch(value))


def _mask_preserving_lines(match: re.Match) -> str:
    return MASK + "\n" * match[0].count("\n")


def redact_text(text: str) -> str:
    """Redact credentials in free text (HTTP values, comments, string literals)."""
    for pattern in _KNOWN_SECRETS:
        text = pattern.sub(_mask_preserving_lines, text)
    text = _BEARER.sub(lambda m: m[1] + m[2] + MASK, text)
    text = _BASIC.sub(
        lambda m: m[1] + m[2] + MASK if len(m[3]) % 4 == 0 or _BASE64_HINT.search(m[3]) else m[0],
        text,
    )
    text = _DIGEST.sub(lambda m: m[1] + m[2] + MASK, text)
    text = _USERINFO.sub(lambda m: m[1] + MASK + "@", text)
    text = _HEADER_LINE.sub(lambda m: m[1] + m[2] + MASK if sensitive(m[1]) else m[0], text)
    text = _QUOTED_ASSIGN.sub(
        lambda m: (
            m[0]
            if not sensitive(m[2]) or _is_placeholder(m[6])
            else m[1] + m[2] + m[1] + m[3] + m[4] + m[5] + MASK + m[5]
        ),
        text,
    )
    text = _KEY_VALUE.sub(
        lambda m: m[0] if not sensitive(m[1]) or _is_placeholder(m[2]) else m[1] + "=" + MASK,
        text,
    )
    return _LOOSE.sub(
        lambda m: m[0] if not sensitive(m[1]) or _is_placeholder(m[3]) else m[1] + m[2] + MASK,
        text,
    )


def redact_name(name: str) -> str:
    """Redact a display name (file name, HTTP field name, call name)."""
    return redact_text(name)


def redact_object(value):
    if isinstance(value, dict):
        return {k: MASK if sensitive(str(k)) else redact_object(v) for k, v in value.items()}
    if isinstance(value, list):
        return [redact_object(item) for item in value]
    return redact_text(value) if isinstance(value, str) else value


_STRING_PARTS = re.compile(r"([A-Za-z]{0,3})('''|\"\"\"|'|\")(.*)\2", re.S)
_ASSIGN_OPS = frozenset({"=", ":", "==", "!=", ":=", "+="})
_STOP_OPS = frozenset({",", "(", "{", "[", ";", "->"})
_FSTRING_START = getattr(tokenize, "FSTRING_START", None)
_FSTRING_END = getattr(tokenize, "FSTRING_END", None)
_FSTRING_MIDDLE = getattr(tokenize, "FSTRING_MIDDLE", None)
_IGNORED = frozenset({tokenize.NL, tokenize.COMMENT, tokenize.INDENT, tokenize.DEDENT})


def _literal_body(token: str) -> str:
    match = _STRING_PARTS.fullmatch(token)
    return match[3] if match else ""


def _sensitive_context(previous: list[tokenize.TokenInfo]) -> bool:
    """A string is a secret value when it is assigned/compared/keyed to a credential name."""
    if not previous or previous[-1].type != tokenize.OP or previous[-1].string not in _ASSIGN_OPS:
        return False
    for token in reversed(previous[-9:-1]):
        if token.type == tokenize.NEWLINE or (
            token.type == tokenize.OP and token.string in _STOP_OPS
        ):
            return False
        if token.type == tokenize.NAME and sensitive(token.string):
            return True
        if token.type == tokenize.STRING and sensitive(_literal_body(token.string)):
            return True
    return False


def redact_source(text: str) -> str:
    """Redact Python source for display/model use without changing code structure or lines.

    Only string literals, f-string bodies and comments are rewritten. If the code cannot be
    tokenized, fall back to line-preserving free-text redaction (AST rules cannot run then).
    """
    try:
        tokens = list(tokenize.generate_tokens(io.StringIO(text).readline))
    except (tokenize.TokenError, SyntaxError, ValueError, RecursionError, MemoryError):
        return _checked(text, redact_text(text))
    starts, offset = [], 0
    for line in text.split("\n"):
        starts.append(offset)
        offset += len(line) + 1

    def position(point: tuple[int, int]) -> int:
        return starts[point[0] - 1] + point[1]

    def located(token: tokenize.TokenInfo) -> bool:
        return text[position(token.start) : position(token.end)] == token.string

    def fstring_literal_edits(inner, start: int, stop: int) -> list[tuple[int, int, str]]:
        """Redact literal fragments of an f-string; mask the whole body if offsets are unsure."""
        found = []
        for part in inner:
            if part.type != _FSTRING_MIDDLE or not part.string:
                continue
            if not located(part):  # e.g. "{{" escapes: token text differs from the source
                raw = text[start:stop]
                changed = redact_text(raw) != raw
                return [(start, stop, MASK + "\n" * raw.count("\n"))] if changed else []
            replacement = redact_text(part.string)
            if replacement != part.string:
                found.append((position(part.start), position(part.end), replacement))
        # Literal strings can also occur inside an interpolation expression, not only
        # FSTRING_MIDDLE tokens (e.g. f"{'Bearer credential'}"). If a credential remains
        # after fragment edits, conservatively mask this body while keeping its lines.
        candidate = text[start:stop]
        for left, right, replacement in sorted(found, reverse=True):
            candidate = candidate[: left - start] + replacement + candidate[right - start :]
        if redact_text(candidate) != candidate:
            return [(start, stop, MASK + "\n" * text.count("\n", start, stop))]
        return found

    edits: list[tuple[int, int, str]] = []
    previous: list[tokenize.TokenInfo] = []
    index = 0
    while index < len(tokens):
        token = tokens[index]
        if _FSTRING_START is not None and token.type == _FSTRING_START:
            depth, end = 1, index + 1
            while end < len(tokens) and depth:
                depth += {_FSTRING_START: 1, _FSTRING_END: -1}.get(tokens[end].type, 0)
                end += 1
            closing = tokens[end - 1]
            if not (located(token) and located(closing)):
                return _checked(text, redact_text(text))
            start, stop = position(token.end), position(closing.start)
            whole = MASK + "\n" * text.count("\n", start, stop)
            if closing.type == _FSTRING_END and stop > start:
                if _sensitive_context(previous):
                    edits.append((start, stop, whole))
                else:
                    edits += fstring_literal_edits(tokens[index + 1 : end - 1], start, stop)
            previous.append(closing)
            index = end
            continue
        if token.type in (tokenize.STRING, tokenize.COMMENT) and not located(token):
            # Offsets disagree with the text (tokenizer edge case): use the safe fallback.
            return _checked(text, redact_text(text))
        if token.type == tokenize.STRING:
            parts = _STRING_PARTS.fullmatch(token.string)
            if parts and parts[3]:
                start = position(token.start) + len(parts[1]) + len(parts[2])
                stop = position(token.end) - len(parts[2])
                body = parts[3]
                if _sensitive_context(previous):
                    replacement = MASK + "\n" * body.count("\n")
                else:
                    replacement = redact_text(body)
                if replacement != body:
                    edits.append((start, stop, replacement))
        elif token.type == tokenize.COMMENT:
            replacement = redact_text(token.string)
            if replacement != token.string:
                edits.append((position(token.start), position(token.end), replacement))
        if token.type not in _IGNORED:
            previous.append(token)
        index += 1
    pieces, cursor = [], 0
    for start, stop, replacement in sorted(edits):
        pieces += [text[cursor:start], replacement]
        cursor = stop
    pieces.append(text[cursor:])
    return _checked(text, "".join(pieces))


def _checked(original: str, redacted: str) -> str:
    # Line numbers are the contract between rules, evidence and chunks; never break it.
    if redacted.count("\n") != original.count("\n"):
        return "\n".join(MASK for _ in original.split("\n"))
    return redacted
