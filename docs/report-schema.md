# Report schema

```json
{
  "decision": "allow",
  "reason_codes": [],
  "notes": [],
  "authorizations": [
    {
      "identifier": "www.example.com",
      "wildcard": false,
      "dns01": {"expected": "...", "observed": ["..."]},
      "caa_node": "www.example.com.",
      "decision": "allow"
    }
  ]
}
```

`reason_codes` uses the names and order in `docs/admit-rules.md`.
