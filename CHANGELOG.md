# Changelog

This crate uses 0.x semantic versions: a minor version changes the public API or a wire format, a patch changes
anything else. There is no API-stability guarantee before 1.0 (see the README).

## Unreleased

- openmls moves to its main branch as of 2026-11-18, the commit `Cargo.toml` pins. Commits list their Update, Remove and SelfRemove
  proposals in ascending leaf order; the other changes are in features this crate does not enable.

## 0.1.0 - 2026-11-15

First release of the cryptographic core of Haven's client, native and WASM, as in production use today.

- **OpenPGP** (rPGP, RFC 4880): key generation, encryption, decryption and signatures for Haven's email.
- **MLS** (openmls, RFC 9420): identity generation from a seed, groups, and the cross-provider MIMI operations,
  including the participant-list path.
- **Primitives:** PBKDF2, AES-GCM, AES-CTR, HKDF-SHA256, HMAC-SHA256, BIP-39 and secure random bytes, with known-answer
  tests against published vectors.
- **Secret store:** a handle-based custodian for a session's long-lived secret material.
- **Sealing:** a small payload sealed to a reader's X25519 key (RFC 9180, Base mode), and data sealed in parts that
  each open and check on their own.
- **Signatures:** detached Ed25519 signatures over exact document bytes (RFC 8032).
- **PAKE:** transcript-bound SPAKE2 with explicit confirmation of a server identity key.
- **Policy seams:** ciphersuite selection in one place (`suite_policy.rs`, with a post-quantum demonstration), and MLS
  external commits and proposals refused by construction (`profile.rs`).
- **Builds:** the WASM build is reproducible byte for byte (`docs/REPRODUCIBLE_BUILDS.md`); a threat model and an
  architecture guide are in `docs/`.
