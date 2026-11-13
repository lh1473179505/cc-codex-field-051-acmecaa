"""Order admission. Not implemented in this snapshot."""

from __future__ import annotations

from typing import Any

from acmecaa.dnszone import Zone


def admit(order: dict[str, Any], account: dict[str, Any], zone: Zone, policy: dict[str, Any]) -> dict[str, Any]:
    raise NotImplementedError("admit is not implemented in this snapshot")
