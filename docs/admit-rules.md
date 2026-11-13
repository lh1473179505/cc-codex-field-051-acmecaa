# Admit rules

Reuse `load_order`, `load_account`, `load_zone`, and `load_policy`. The zone file is a recorded DNS snapshot; this lab makes no network calls. `inspect` already computes the account JWK thumbprint, the expected dns-01 TXT value, follows CNAMEs for the challenge name, and lists CAA rows walking toward the public suffix. `admit` still has to make the allow/deny decision. Standard library only. No Docker.

`load_account` fills `account.thumbprint` from `account.jwk` using RFC 7638 (required members only, lexicographic JSON, SHA-256, base64url without padding). Reuse that value. `acmecaa.jwk.thumbprint` and `acmecaa.caa.parse_rdata` are available.

## Identifiers and challenges

Each entry in `order.authorizations` is one identifier.

- `identifier.type` must be `dns`. Anything else is `unsupported_identifier`.
- `identifier.value` is an LDH name, optionally with a `*.` prefix. A leading `*.` or `authorization.wildcard` true means this is a wildcard order. The CAA target and the dns-01 name both drop the `*.` prefix: `*.shop.example.com` is evaluated at `shop.example.com`, and the TXT name is `_acme-challenge.shop.example.com`.
- Among `challenges`, there must be one with `type` in `policy.allowed_challenge_types` (the public policy only allows `dns-01`). If none, `challenge_unsupported`. Ignore other challenge types.
- Use that dns-01 challenge's `token`. The key authorization is `token + "." + account.thumbprint`. The expected TXT rdata is base64url(SHA-256 of the key authorization, no padding).

## dns-01 lookup

Look up TXT at `_acme-challenge.<caa-target>` in the zone.

Follow CNAME records only for this challenge lookup, at most `policy.max_cname` hops (default 3). A CNAME cycle, more than one CNAME at the same name, or exceeding the hop limit is `cname_loop`. Do not follow CNAME when looking up CAA.

After following, if there is no TXT record, `dns01_missing`. If at least one TXT rdata equals the expected value, the dns-01 check passes (extra TXT records are allowed). If TXT records exist but none match, `dns01_mismatch`. TXT rdata in the snapshot is already unquoted.

Name comparison is case-insensitive. Names may be written with or without a trailing dot; treat them as FQDNs.

## CAA search

CAA uses a different walk from the challenge CNAME.

1. Start at the CAA target (the identifier with `*.` removed).
2. At each node, if the name is in `policy.public_suffixes` (compared as FQDNs, no trailing-dot difference), stop. Do not use CAA records on a public suffix.
3. Otherwise, take every CAA record at that exact name. Do not follow CNAME at this node for CAA.
4. If any CAA records exist there, that set is the chosen set. Stop walking.
5. If none, move to the parent and repeat. If the walk ends without a chosen set, the set is empty.

## Applying a CAA set

Known tags in this lab: `issue`, `issuewild`, `iodef`, `contactemail`, `contactphone`, `issuemail`. `acmecaa.caa.parse_rdata` returns `flags`, `tag`, `issuer`, `params`, and `critical` (flag bit 7, value 128).

- If any record in the chosen set is critical and its tag is not in the known list, deny `caa_critical_unknown`. Still collect the other codes that apply.
- Relevant tag: if this authorization is a wildcard and the chosen set contains at least one `issuewild` record, use only `issuewild`. Otherwise use only `issue`. Other tags are ignored for the grant decision (except the critical-unknown rule above).
- An empty relevant subset (for example only `iodef` is present) is `caa_denied`.
- A record with an empty issuer (the value is empty or `;`) is a deny for that tag; it is not a grant.
- A granting record has issuer equal to `policy.ca_domain` (case-insensitive, ignore a trailing dot) and:
  - if the record has an `accounturi` parameter, it must equal `account.url` exactly;
  - if `policy.require_accounturi` is true, a granting record must include `accounturi`;
  - if the record has a `validationmethods` parameter, the comma-separated list (trimmed, case-insensitive) must include `dns-01`.
- If at least one relevant record is granting, the CAA check passes. If none are granting, use `accounturi_mismatch` when every otherwise-matching issuer failed only on `accounturi`, `validationmethods_mismatch` when every otherwise-matching issuer failed only on `validationmethods`, and `caa_denied` in the remaining cases. If both parameter failures appear across records, include both parameter codes and do not also add `caa_denied`.

Empty CAA set (the walk found no CAA records before the public suffix):

- `policy.empty_caa` is `allow` (the public default) → CAA passes.
- `policy.empty_caa` is `deny` → `empty_caa_denied`.

## Report and exit

A report covers the whole order. Any authorization that fails makes the order `deny`, but collect reason codes from every authorization (unique, stable order below).

- `decision`: `allow` or `deny`.
- `reason_codes` in this order, only those that apply: `unsupported_identifier`, `challenge_unsupported`, `dns01_missing`, `dns01_mismatch`, `cname_loop`, `caa_critical_unknown`, `empty_caa_denied`, `accounturi_mismatch`, `validationmethods_mismatch`, `caa_denied`.
- `notes`: short strings, may be empty. Mention the identifier when useful.
- `authorizations`: a list of `{identifier, wildcard, dns01, caa_node, decision}` summaries. `dns01` may include `expected` and `observed`. `caa_node` is the FQDN whose CAA set was used, or null if the set was empty.

Allow only when `reason_codes` is empty. Unreadable input or a report without `decision` is exit 2, not a deny report.

Exit: allow 0, deny 1, load/parse failure 2.

## Public fixtures

Default files: `--account fixtures/account.json --policy fixtures/policy.json --order fixtures/orders/NAME.json --zone fixtures/zones/NAME.json`.

- `ok-www.json` → allow (CAA on `www.example.com` grants this CA, including accounturi and dns-01).
- `ok-empty-caa.json` → allow (no CAA records, `empty_caa` is allow).
- `ok-cname-challenge.json` → allow (the challenge name is a CNAME to a TXT; CAA stays on the identifier and is not followed).
- `ok-wildcard.json` → allow (`*.shop.example.com`, `issuewild` grants).
- `ok-parent-caa.json` → allow (no CAA at `www.example.com`, parent `example.com` grants).
- `deny-wrong-txt.json` → deny `dns01_mismatch`.
- `deny-dns01-missing.json` → deny `dns01_missing`.
- `deny-caa-issue.json` → deny `caa_denied` (`issue ";"` on the identifier).
- `deny-accounturi.json` → deny `accounturi_mismatch`.
- `deny-validationmethods.json` → deny `validationmethods_mismatch` (`validationmethods=http-01`).
- `deny-issuewild.json` → deny `caa_denied` (wildcard; node has `issuewild ";"` plus a non-wildcard `issue` for this CA — `issuewild` is present, so `issue` must be ignored).
- `deny-critical-unknown.json` → deny `caa_critical_unknown`.
- `deny-wrong-ca.json` → deny `caa_denied`.
- `deny-cname-loop.json` → deny `cname_loop`.
