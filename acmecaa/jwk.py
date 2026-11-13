"""RFC 7638 JWK thumbprint for the account key."""

from __future__ import annotations

import hashlib
import json
from typing import Any

from acmecaa.b64 import b64u_encode


class JwkError(ValueError):
    pass


def canonical_jwk(jwk: dict[str, Any]) -> str:
    kty = jwk.get("kty")
    if kty == "EC":
        keys = ("crv", "kty", "x", "y")
    elif kty == "RSA":
        keys = ("e", "kty", "n")
    elif kty == "OKP":
        keys = ("crv", "kty", "x")
    else:
        raise JwkError(f"unsupported kty {kty!r}")
    missing = [k for k in keys if not isinstance(jwk.get(k), str) or not jwk[k]]
    if missing:
        raise JwkError(f"jwk missing {missing}")
    obj = {k: jwk[k] for k in keys}
    return json.dumps(obj, separators=(",", ":"), sort_keys=True, ensure_ascii=False)


def thumbprint(jwk: dict[str, Any]) -> str:
    return b64u_encode(hashlib.sha256(canonical_jwk(jwk).encode("utf-8")).digest())
