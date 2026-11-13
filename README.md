# acmecaa

A lab admission tool for an internal ACME CA. It checks dns-01 key authorizations against a recorded zone, then applies CAA (issue / issuewild, accounturi, validationmethods, critical unknown properties).

`inspect` already prints the thumbprint, expected TXT, CNAME chain, and CAA walk. `admit` is still a stub in this snapshot.

Standard library only. No Docker, no live DNS, no network.
