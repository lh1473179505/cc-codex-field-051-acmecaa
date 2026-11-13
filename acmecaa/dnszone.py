"""Load a recorded zone snapshot and answer TXT / CNAME / CAA lookups. No network."""

from __future__ import annotations

from typing import Any

from acmecaa.names import fqdn


class ZoneError(ValueError):
    pass


def normalize_record(rec: dict[str, Any]) -> dict[str, Any]:
    try:
        name = fqdn(rec["name"])
        typ = str(rec["type"]).upper()
        rdata = rec["rdata"]
    except (KeyError, ValueError, TypeError) as exc:
        raise ZoneError(f"bad record {rec!r}: {exc}") from exc
    if typ in {"TXT", "CNAME"} and not isinstance(rdata, str):
        raise ZoneError(f"{typ} rdata must be a string")
    if typ == "CNAME":
        rdata = fqdn(rdata)
    if typ == "CAA" and not isinstance(rdata, str):
        raise ZoneError("CAA rdata must be a string")
    return {"name": name, "type": typ, "ttl": int(rec.get("ttl", 0) or 0), "rdata": rdata}


class Zone:
    def __init__(self, records: list[dict[str, Any]]):
        self.records = [normalize_record(r) for r in records]

    def lookup(self, name: str, typ: str) -> list[dict[str, Any]]:
        want = fqdn(name)
        typ = typ.upper()
        return [r for r in self.records if r["name"] == want and r["type"] == typ]

    def follow_cname(self, name: str, typ: str, max_cname: int) -> dict[str, Any]:
        """Follow CNAMEs at most max_cname times, then look up typ at the terminal name."""
        seen: list[str] = []
        current = fqdn(name)
        hops = 0
        while hops <= max_cname:
            if current in seen:
                return {"error": "cname_loop", "chain": seen + [current], "records": []}
            seen.append(current)
            direct = self.lookup(current, typ)
            if direct:
                return {"error": None, "chain": seen, "records": direct, "terminal": current}
            cnames = self.lookup(current, "CNAME")
            if not cnames:
                return {"error": None, "chain": seen, "records": [], "terminal": current}
            if len(cnames) != 1:
                return {"error": "cname_loop", "chain": seen, "records": []}
            current = fqdn(cnames[0]["rdata"])
            hops += 1
        return {"error": "cname_loop", "chain": seen, "records": []}
