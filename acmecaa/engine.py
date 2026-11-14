"""Order admission: dns-01 check against the snapshot, then CAA evaluation."""

from __future__ import annotations

import hashlib
from typing import Any

from acmecaa.b64 import b64u_encode
from acmecaa.caa import KNOWN_TAGS, CaaError, parse_rdata
from acmecaa.dnszone import Zone
from acmecaa.names import fqdn, is_public_suffix, parent


REASON_ORDER = (
    "unsupported_identifier",
    "challenge_unsupported",
    "dns01_missing",
    "dns01_mismatch",
    "cname_loop",
    "caa_critical_unknown",
    "empty_caa_denied",
    "accounturi_mismatch",
    "validationmethods_mismatch",
    "caa_denied",
)


def _expected_txt(token: str, thumbprint: str) -> str:
    key_authorization = f"{token}.{thumbprint}"
    return b64u_encode(hashlib.sha256(key_authorization.encode("ascii")).digest())


def _evaluate_grant(record: dict[str, Any], account: dict[str, Any], policy: dict[str, Any]) -> tuple[bool, set[str]]:
    """Return (grants, parameter failure tags) for one issue/issuewild record."""
    issuer = record["issuer"]
    if not issuer or issuer != policy["ca_domain"]:
        return False, set()
    params = record["params"]
    failures: set[str] = set()
    if "accounturi" in params:
        if params["accounturi"] != account["url"]:
            failures.add("accounturi")
    elif policy.get("require_accounturi"):
        failures.add("accounturi")
    if "validationmethods" in params:
        methods = [part.strip().lower() for part in params["validationmethods"].split(",")]
        if "dns-01" not in methods:
            failures.add("validationmethods")
    return not failures, failures


def _check_dns01(auth: dict[str, Any], target: str, account: dict[str, Any], zone: Zone, policy: dict[str, Any]) -> tuple[set[str], list[str], dict[str, Any] | None]:
    reasons: set[str] = set()
    notes: list[str] = []
    allowed_types = policy.get("allowed_challenge_types") or ["dns-01"]
    challenge = next(
        (
            ch
            for ch in auth.get("challenges") or []
            if ch.get("type") in allowed_types and isinstance(ch.get("token"), str)
        ),
        None,
    )
    if challenge is None:
        reasons.add("challenge_unsupported")
        notes.append(f"{target}: no challenge of type {sorted(allowed_types)}")
        return reasons, notes, None

    expected = _expected_txt(challenge["token"], account["thumbprint"])
    lookup = zone.follow_cname(
        fqdn(f"_acme-challenge.{target}"),
        "TXT",
        int(policy.get("max_cname", 3)),
    )
    observed = [record["rdata"] for record in lookup["records"]]
    summary = {"expected": expected, "observed": observed}
    if lookup.get("error") == "cname_loop":
        reasons.add("cname_loop")
        notes.append(f"{target}: CNAME loop or hop limit while resolving dns-01 challenge")
    elif not observed:
        reasons.add("dns01_missing")
        notes.append(f"{target}: no TXT record at the dns-01 challenge name")
    elif expected not in observed:
        reasons.add("dns01_mismatch")
        notes.append(f"{target}: dns-01 TXT does not match expected value")
    return reasons, notes, summary


def _find_caa_set(target: str, zone: Zone, policy: dict[str, Any]) -> tuple[list[dict[str, Any]] | None, str | None, list[str]]:
    """Walk parents without following CNAME; return (parsed set, node fqdn, notes)."""
    suffixes = policy.get("public_suffixes") or ["com", "net", "org"]
    notes: list[str] = []
    current = fqdn(target)
    seen: set[str] = set()
    while current not in seen:
        seen.add(current)
        if is_public_suffix(current, suffixes):
            break
        rows = zone.lookup(current, "CAA")
        if rows:
            parsed: list[dict[str, Any]] = []
            for row in rows:
                try:
                    parsed.append(parse_rdata(row["rdata"]))
                except CaaError as exc:
                    notes.append(f"{current}: unparseable CAA rdata {row['rdata']!r}: {exc}")
            return parsed, current, notes
        nxt = parent(current)
        if nxt is None:
            break
        current = nxt
    return None, None, notes


def _check_caa(target: str, wildcard: bool, account: dict[str, Any], zone: Zone, policy: dict[str, Any]) -> tuple[set[str], list[str], str | None]:
    reasons: set[str] = set()
    notes: list[str] = []
    caa_set, caa_node, walk_notes = _find_caa_set(target, zone, policy)
    notes.extend(walk_notes)
    if caa_set is None:
        if policy.get("empty_caa", "allow") == "deny":
            reasons.add("empty_caa_denied")
            notes.append(f"{target}: no CAA records and policy.empty_caa is deny")
        return reasons, notes, caa_node

    for record in caa_set:
        if record["critical"] and record["tag"] not in KNOWN_TAGS:
            reasons.add("caa_critical_unknown")
            notes.append(f"{caa_node}: critical unknown CAA tag {record['tag']!r}")

    tag = "issuewild" if wildcard and any(record["tag"] == "issuewild" for record in caa_set) else "issue"
    relevant = [record for record in caa_set if record["tag"] == tag]
    if not relevant:
        reasons.add("caa_denied")
        notes.append(f"{caa_node}: CAA set has no {tag} record")
        return reasons, notes, caa_node

    failures: set[str] = set()
    granted = False
    for record in relevant:
        ok, record_failures = _evaluate_grant(record, account, policy)
        granted = granted or ok
        failures.update(record_failures)
    if granted:
        return reasons, notes, caa_node

    if failures == {"accounturi"}:
        reasons.add("accounturi_mismatch")
    elif failures == {"validationmethods"}:
        reasons.add("validationmethods_mismatch")
    elif failures == {"accounturi", "validationmethods"}:
        reasons.add("accounturi_mismatch")
        reasons.add("validationmethods_mismatch")
    else:
        reasons.add("caa_denied")
        notes.append(f"{caa_node}: no {tag} record grants {policy['ca_domain']}")
    return reasons, notes, caa_node


def admit(order: dict[str, Any], account: dict[str, Any], zone: Zone, policy: dict[str, Any]) -> dict[str, Any]:
    all_reasons: set[str] = set()
    notes: list[str] = []
    authorizations: list[dict[str, Any]] = []

    for auth in order.get("authorizations") or []:
        ident = auth.get("identifier") or {}
        value = ident.get("value")
        value = value if isinstance(value, str) else ""
        wildcard = bool(auth.get("wildcard") or value.startswith("*."))
        target = value[2:] if value.startswith("*.") else value
        auth_reasons: set[str] = set()
        auth_notes: list[str] = []
        dns01_summary: dict[str, Any] | None = None
        caa_node: str | None = None

        if ident.get("type") != "dns" or not target:
            auth_reasons.add("unsupported_identifier")
            auth_notes.append(f"{value or ident!r}: only dns identifiers are supported")
        else:
            dns_reasons, dns_notes, dns01_summary = _check_dns01(auth, target, account, zone, policy)
            auth_reasons.update(dns_reasons)
            auth_notes.extend(dns_notes)
            caa_reasons, caa_notes, caa_node = _check_caa(target, wildcard, account, zone, policy)
            auth_reasons.update(caa_reasons)
            auth_notes.extend(caa_notes)

        all_reasons.update(auth_reasons)
        notes.extend(auth_notes)
        authorizations.append(
            {
                "identifier": value if value else ident,
                "wildcard": wildcard,
                "dns01": dns01_summary,
                "caa_node": caa_node,
                "decision": "deny" if auth_reasons else "allow",
            }
        )

    reason_codes = [code for code in REASON_ORDER if code in all_reasons]
    return {
        "decision": "allow" if not reason_codes else "deny",
        "reason_codes": reason_codes,
        "notes": notes,
        "authorizations": authorizations,
    }
