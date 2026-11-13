"""Load account, policy, order, and recorded zone snapshots."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from acmecaa.dnszone import Zone, ZoneError
from acmecaa.jwk import JwkError, thumbprint


class LoadError(ValueError):
    pass


def load_json(path: str | Path) -> dict[str, Any]:
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise LoadError(f"cannot read {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise LoadError(f"{path} must contain a JSON object")
    return data


def load_account(path: str | Path) -> dict[str, Any]:
    acc = load_json(path)
    if not isinstance(acc.get("url"), str) or not acc["url"]:
        raise LoadError("account.url must be a non-empty string")
    jwk = acc.get("jwk")
    if not isinstance(jwk, dict):
        raise LoadError("account.jwk must be an object")
    try:
        acc["thumbprint"] = thumbprint(jwk)
    except JwkError as exc:
        raise LoadError(f"account.jwk: {exc}") from exc
    return acc


def load_policy(path: str | Path) -> dict[str, Any]:
    policy = load_json(path)
    if not isinstance(policy.get("ca_domain"), str) or not policy["ca_domain"]:
        raise LoadError("policy.ca_domain is required")
    policy["ca_domain"] = policy["ca_domain"].lower().rstrip(".")
    policy.setdefault("empty_caa", "allow")
    policy.setdefault("public_suffixes", ["com", "net", "org"])
    policy.setdefault("max_cname", 3)
    policy.setdefault("allowed_challenge_types", ["dns-01"])
    policy.setdefault("require_accounturi", False)
    if not isinstance(policy["public_suffixes"], list):
        raise LoadError("policy.public_suffixes must be a list")
    return policy


def load_order(path: str | Path) -> dict[str, Any]:
    order = load_json(path)
    auths = order.get("authorizations")
    if not isinstance(auths, list) or not auths:
        raise LoadError("order.authorizations must be a non-empty list")
    for i, auth in enumerate(auths):
        if not isinstance(auth, dict):
            raise LoadError(f"authorization #{i} must be an object")
        ident = auth.get("identifier")
        if not isinstance(ident, dict) or ident.get("type") != "dns" or not isinstance(ident.get("value"), str):
            # still return the object; admit will flag unsupported identifiers
            continue
    return order


def load_zone(path: str | Path) -> Zone:
    raw = load_json(path)
    recs = raw.get("records")
    if not isinstance(recs, list):
        raise LoadError("zone.records must be a list")
    try:
        return Zone(recs)
    except ZoneError as exc:
        raise LoadError(str(exc)) from exc
