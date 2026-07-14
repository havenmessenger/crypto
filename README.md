# Haven Crypto

The cryptographic core of [Haven](https://havenmessenger.com) - a private, end-to-end
encrypted email and messaging service.

This crate implements Haven's OpenPGP and MLS-related cryptographic primitives (native +
WASM). It is published openly and independently so that the security claim Haven makes -
*"only you and the people you're writing to can read your messages, not even us"* - can be
inspected and verified by anyone, not taken on faith.

> **Status: pre-audit, v0.1.0.** This is Haven's production cryptography, in use today. No
> API-stability guarantee yet - this is not a general-purpose crypto library; it implements the
> specific primitives Haven's client needs. See
> [`havenmessenger/client`](https://github.com/havenmessenger/client) for how this crate is used.

## Why use this
- **It ships.** This is production cryptography, not a research crate. The byte-compat
  fixtures in the test suite lock the wire formats real deployed clients already use.
- **One core, every platform.** The same crate compiles native (Android, iOS, desktop) and
  to WASM (web), so the cryptography is byte-identical across platforms rather than
  reimplemented per platform.
- **Known-answer discipline.** 172 tests gate every change: KATs against published RFC and
  NIST vectors, fail-closed proofs, and zeroize-on-drop proofs.
- **Vetted primitives only.** openmls (MLS, [RFC 9420](https://www.rfc-editor.org/rfc/rfc9420)),
  rPGP ([RFC 4880](https://www.rfc-editor.org/rfc/rfc4880)), and the RustCrypto suite (AES-GCM,
  HKDF, SHA-2, ed25519-dalek). No hand-rolled ciphers.
- **Crypto-agility built in.** Ciphersuite selection is one policy seam
  (`src/suite_policy.rs`); adding a post-quantum suite is a config-and-KAT change, not a
  wire rewrite. A working PQ demo (`src/suite_policy_pq_demo.rs`) proves the seam is
  config-driven.
- **Deny-by-default external MLS operations.** External commits and external proposals are
  refused structurally (`src/profile.rs`), with negative tests proving each refusal.
- **Reproducible.** Two independent builds produce byte-identical artifacts; the recipe is
  [`docs/REPRODUCIBLE_BUILDS.md`](docs/REPRODUCIBLE_BUILDS.md) and CI runs it.
- **A written threat model.** [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) covers what
  this code protects against and what it does not.
- **A documented module map.** [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) is the orientation
  guide for the code layout.

Every claim above is backed by tests or docs in this repository; check any of them. We are
arranging an independent third-party security audit; until then, no outside party has
reviewed this code.

## Why this is open
- **The privacy claim is checkable here.** It rests on what this code does with keys:
  read how they are generated, stored, and used.
- **No hand-rolled ciphers.** The crate composes openmls, rPGP, and the RustCrypto suite
  (AES-GCM, HKDF, SHA-2, ed25519-dalek); known-answer tests against published RFC/NIST
  vectors gate every change.
- **A third-party security audit is planned.** This standalone crate is its scope;
  [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) carries the threat model and the known
  residuals ahead of it.

## What lives here (and what does not)
**Here (open):** the cryptographic primitives and key-handling logic the client depends on.
**Not here (closed, by design):** Haven's production deployment and operational
infrastructure. The server is untrusted by design.

## Building / testing
```
git clone https://github.com/havenmessenger/crypto.git
cd crypto
cargo build
cargo test --release
```
No submodules, no external services, no network access beyond crates.io during the initial
dependency fetch. A clean build + full test run (172 tests: known-answer vectors against
published RFC/NIST test data, plus fail-closed and zeroize proofs) takes about two minutes on
a typical machine. Known-answer tests are the gate for any change - see `CONTRIBUTING.md`.

Native builds (Android, iOS, desktop) use the stable toolchain pinned in
[`rust-toolchain.toml`](rust-toolchain.toml) (currently 1.96.0, this crate's MSRV). The WASM
target additionally needs `nightly-2026-03-28` - see
[`docs/REPRODUCIBLE_BUILDS.md`](docs/REPRODUCIBLE_BUILDS.md) for why, and for the full repro
recipe.

## License
Copyright 2026 The Haven Authors. Licensed under
[AGPL-3.0-or-later](LICENSE). The interoperability library
([havenmessenger/interop](https://github.com/havenmessenger/interop)) is Apache-2.0.

## Verifying builds
Reproducible-build instructions: [`docs/REPRODUCIBLE_BUILDS.md`](docs/REPRODUCIBLE_BUILDS.md).

## Security
Found a vulnerability? See [`SECURITY.md`](SECURITY.md) - please use coordinated disclosure.
Cross-cutting design invariants this code is built to (and the reasoning behind each) are
indexed in [`SECURITY-INVARIANTS.md`](SECURITY-INVARIANTS.md).
