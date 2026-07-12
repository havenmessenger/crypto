# Security Invariants

<!-- AUTO-GENERATED - DO NOT EDIT BY HAND. Generated from and kept in sync with this crate's
     design invariants. -->

This file resolves the `// WHY: INV-*` references cited in this repo's source. Only
invariants cited in this repo are included; the full registry also covers concerns
outside this repo's scope. Each entry states a design invariant, the reason it holds,
and the change-control it is under in Haven's development workflow (pre-commit checks
and code review).

## `INV-KEY-001` - Identity private keys are stored only as passphrase-protected armor; decrypted keys are memory-only

**Severity:** critical · **Change control:** security review required

Private keys at rest exist only as passphrase-protected OpenPGP armor. Decryption happens
in memory, scoped to the selected identity, and decrypted key material is never persisted
or handed out of the process in raw form.

## `INV-MAIL-026` - Outbound PGP/MIME generation is single-source: one shared Rust implementation builds every encrypted message

**Severity:** high · **Change control:** security review required

The client and the server build outbound PGP/MIME through the same Rust code path, so
there is exactly one implementation of the wire format and it cannot fork. Per RFC 3156
the encrypted payload part is a bare application/octet-stream (no name or
Content-Disposition parameters). Changes to generation are gated by a conformance test
suite.

## `INV-MIMI-003` - The MIMI lane and the native messaging lane are separate; cross-provider MLS cannot alter the native wire format

**Severity:** high · **Change control:** security review required

Cross-provider (MIMI) messaging runs on its own lane with its own endpoints.
Haven-to-Haven messaging keeps its existing wire format, unchanged by MIMI work, and a
change on the MIMI side is not reachable from the native send or receive path. The two
lanes evolve independently, which is what lets the MIMI lane track moving IETF drafts
without putting the native protocol at risk.

## `INV-MLS-001b` - External proposals are refused in the native lane; the MIMI lane accepts only a pre-configured hub's Remove proposals, each requiring an explicit member commit

**Severity:** high · **Change control:** security review required

RFC 9420 external proposals (Sender::External) are refused in native messaging. The MIMI
lane accepts exactly one narrow case: a Remove proposal from the group's single
allowlisted hub credential - and even then the proposal is inert until an existing member
explicitly includes it in a commit. Nothing is auto-committed. Both the refusals and the
narrow acceptance path are negative-tested.

## `INV-MLS-002` - The MLS ciphersuite is pinned two-sided to 0x0001: generation uses only it, and inbound objects under any other suite are rejected before openmls

**Severity:** high · **Change control:** security review required

Haven generates MLS objects only under suite 0x0001
(MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519) and rejects any inbound MLS object
carrying a different suite before it reaches openmls. A suite change is a wire-format
event: it goes through one policy seam rather than scattered constants, and is gated by
known-answer tests. This is also the crypto-agility seam - adding a post-quantum suite is
a change to configuration and vectors, not a rewrite.
