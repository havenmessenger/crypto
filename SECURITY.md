# Security Policy

Haven is a privacy and security product. Coordinated disclosure from security researchers
is welcome.

## Reporting a vulnerability
- **GitHub Security Advisories:** you can also report privately via this repository's
  [Security Advisories](https://github.com/havenmessenger/crypto/security/advisories/new) tab.
- **Email:** security@havenmessenger.com
- **Encrypted reports:** the disclosure PGP key is published at
  [`havenmessenger.com/.well-known/security.txt`](https://havenmessenger.com/.well-known/security.txt).
  Please encrypt reports that contain sensitive detail (exploit steps, affected users).
- **Please do not** open a public issue, pull request, or discussion for a security-sensitive
  report - use the email channel so we can coordinate disclosure.
- **Include:** affected component, version/commit hash, reproduction steps, and an impact
  assessment.

## What to expect
- **Acknowledgement within 3 business days** that we received your report.
- An initial assessment and a **coordinated-disclosure timeline agreed with you** - we target
  public disclosure within **90 days**, sooner for a fix that is ready, later only by mutual
  agreement for a complex issue.
- Credit in the advisory if you wish (or anonymity if you prefer).

## Safe harbor
We will not pursue or support legal action against researchers who, in good faith, discover and
report a vulnerability under this policy - provided you avoid privacy violations against other
users, service degradation, and data destruction, and give us reasonable time to remediate
before any public disclosure. Good-faith security research is authorized.

## Scope
**In scope:** this repository - Haven's cryptographic core (the OpenPGP and MLS-related
primitives, key generation/handling logic, and the known-answer tests that gate them).

**Out of scope (different process):** Haven's production deployment and operational
infrastructure. You may report those to the same address, but note they are not in this repo
and are assessed separately.
