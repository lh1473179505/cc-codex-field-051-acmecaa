"""CLI. inspect already works; admit is the piece to implement."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

from acmecaa.b64 import b64u_encode
from acmecaa.caa import CaaError, parse_rdata
from acmecaa.load import LoadError, load_account, load_order, load_policy, load_zone
from acmecaa.names import fqdn, parent


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="acmecaa")
    sub = p.add_subparsers(dest="cmd", required=True)
    ins = sub.add_parser("inspect", help="show order, expected dns-01 TXT, and CAA rows")
    ins.add_argument("--order", required=True)
    ins.add_argument("--account", required=True)
    ins.add_argument("--zone", required=True)
    ins.add_argument("--policy", required=False)
    adm = sub.add_parser("admit", help="decide whether the CA may issue for this order")
    adm.add_argument("--order", required=True)
    adm.add_argument("--account", required=True)
    adm.add_argument("--zone", required=True)
    adm.add_argument("--policy", required=True)
    adm.add_argument("--report", required=True)
    return p


def key_authorization(token: str, thumbprint: str) -> str:
    return f"{token}.{thumbprint}"


def expected_txt(token: str, thumbprint: str) -> str:
    ka = key_authorization(token, thumbprint)
    return b64u_encode(hashlib.sha256(ka.encode("ascii")).digest())


def challenge_name(ident_value: str) -> str:
    value = ident_value[2:] if ident_value.startswith("*.") else ident_value
    return fqdn(f"_acme-challenge.{value}")


def inspect_payload(order, account, zone, policy) -> dict:
    max_cname = int((policy or {}).get("max_cname", 3))
    out = {
        "account_url": account["url"],
        "thumbprint": account["thumbprint"],
        "authorizations": [],
    }
    for auth in order.get("authorizations") or []:
        ident = auth.get("identifier") or {}
        value = ident.get("value")
        wildcard = bool(auth.get("wildcard") or (isinstance(value, str) and value.startswith("*.")))
        item = {
            "identifier": ident,
            "wildcard": wildcard,
            "challenges": [],
            "caa_walk": [],
        }
        for ch in auth.get("challenges") or []:
            token = ch.get("token")
            rec = {"type": ch.get("type"), "token": token, "status": ch.get("status")}
            if ch.get("type") == "dns-01" and isinstance(token, str) and value:
                name = challenge_name(value)
                rec["txt_name"] = name
                rec["expected_txt"] = expected_txt(token, account["thumbprint"])
                rec["lookup"] = zone.follow_cname(name, "TXT", max_cname)
            item["challenges"].append(rec)
        if isinstance(value, str):
            start = value[2:] if value.startswith("*.") else value
            cur = fqdn(start)
            suffixes = (policy or {}).get("public_suffixes") or ["com", "net", "org"]
            from acmecaa.names import is_public_suffix

            seen = set()
            while cur and cur not in seen:
                seen.add(cur)
                if is_public_suffix(cur, suffixes):
                    item["caa_walk"].append({"name": cur, "public_suffix": True, "records": []})
                    break
                recs = []
                for r in zone.lookup(cur, "CAA"):
                    try:
                        recs.append({"rdata": r["rdata"], "parsed": parse_rdata(r["rdata"])})
                    except CaaError as exc:
                        recs.append({"rdata": r["rdata"], "error": str(exc)})
                item["caa_walk"].append({"name": cur, "public_suffix": False, "records": recs})
                nxt = parent(cur)
                if nxt is None:
                    break
                cur = nxt
        out["authorizations"].append(item)
    return out


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    try:
        order = load_order(args.order)
        account = load_account(args.account)
        zone = load_zone(args.zone)
        policy = load_policy(args.policy) if getattr(args, "policy", None) else None
    except (LoadError, OSError) as exc:
        print(f"failed to load inputs: {exc}", file=sys.stderr)
        return 2
    if args.cmd == "inspect":
        print(json.dumps(inspect_payload(order, account, zone, policy), ensure_ascii=False, indent=2))
        return 0
    if args.cmd == "admit":
        if policy is None:
            print("policy is required for admit", file=sys.stderr)
            return 2
        from acmecaa.engine import admit
        try:
            report = admit(order, account, zone, policy)
        except NotImplementedError as exc:
            print(str(exc), file=sys.stderr)
            return 2
        Path(args.report).parent.mkdir(parents=True, exist_ok=True)
        Path(args.report).write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        decision = str(report.get("decision", "")).lower()
        if decision == "allow":
            return 0
        if decision == "deny":
            return 1
        print("report is missing a decision of allow or deny", file=sys.stderr)
        return 2
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
