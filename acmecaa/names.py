"""FQDN helpers for the lab (LDH names only)."""

from __future__ import annotations


def fqdn(name: str) -> str:
    n = name.strip().lower().rstrip(".")
    if not n:
        raise ValueError("empty name")
    return n + "."


def labels(name: str) -> list[str]:
    n = fqdn(name)
    return n[:-1].split(".")


def parent(name: str) -> str | None:
    labs = labels(name)
    if len(labs) <= 1:
        return None
    return ".".join(labs[1:]) + "."


def is_public_suffix(name: str, suffixes: list[str]) -> bool:
    n = fqdn(name)[:-1]
    want = {fqdn(s)[:-1] for s in suffixes}
    return n in want
