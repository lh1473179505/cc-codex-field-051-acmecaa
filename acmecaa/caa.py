"""Parse CAA rdata strings used in the recorded zone."""

from __future__ import annotations

from typing import Any


class CaaError(ValueError):
    pass


def parse_rdata(rdata: str) -> dict[str, Any]:
    """Parse 'FLAGS TAG VALUE' where VALUE may be quoted and contain parameters."""
    text = rdata.strip()
    if not text:
        raise CaaError("empty CAA rdata")
    parts = text.split(None, 2)
    if len(parts) < 2:
        raise CaaError(f"CAA rdata needs flags and tag: {rdata!r}")
    try:
        flags = int(parts[0])
    except ValueError as exc:
        raise CaaError(f"CAA flags must be an integer: {rdata!r}") from exc
    tag = parts[1].lower()
    raw_value = parts[2] if len(parts) == 3 else ""
    value = _unquote(raw_value)
    issuer, params = _split_value(value)
    return {"flags": flags, "tag": tag, "value": value, "issuer": issuer, "params": params, "critical": bool(flags & 128)}


def _unquote(value: str) -> str:
    v = value.strip()
    if len(v) >= 2 and v[0] == v[-1] and v[0] in {'"', "'"}:
        return v[1:-1]
    return v


def _split_value(value: str) -> tuple[str, dict[str, str]]:
    # issuer is the token before the first semicolon; parameters are key=value after that.
    text = value.strip()
    if not text:
        return "", {}
    if text == ";":
        return "", {}
    chunks = [c.strip() for c in text.split(";")]
    issuer = chunks[0].strip().lower()
    params: dict[str, str] = {}
    for chunk in chunks[1:]:
        if not chunk:
            continue
        if "=" not in chunk:
            raise CaaError(f"CAA parameter missing '=': {chunk!r}")
        k, val = chunk.split("=", 1)
        params[k.strip().lower()] = _unquote(val.strip())
    return issuer, params


KNOWN_TAGS = frozenset({"issue", "issuewild", "iodef", "contactemail", "contactphone", "issuemail"})
