# Changelog

This crate uses 0.x semantic versions: a minor version changes the public API or a wire format, a patch changes
anything else. There is no API-stability guarantee before 1.0 (see the README).

## Unreleased

- Read-only views for the MIMI lane (`mimi::view`): a group as its member's state has it (epoch, suite, own leaf, each
  leaf's identity, credential type and lifetime, GroupContext extensions and app data components), a KeyPackage as
  published (suite, lifetime, extensions, capabilities, last-resort mark; its signature checked, its lifetime shown even
  when it has ended), and a processed Commit
  (`mimi_process_commit_summarized`, and `mimi_process_commit_app_data_summarized` under `mimi-app-data`: the epoch it
  moved to, its committer, its proposals by type and whether it carried a path). No view carries secret material, and reading one changes no state.
- A feature, `mimi-app-data` (off by default), for MIMI rooms whose state lives in the GroupContext's app data dictionary
  and changes by AppDataUpdate proposals (draft-ietf-mls-extensions §4.6-4.7, draft-ietf-mimi-room-policy): identities
  and groups that support it, a staged commit that adds and removes members with AppDataUpdates, processing such a
  commit, and a leave by proposals (a Remove of the leaver's own leaf and its AppDataUpdates) that the next commit
  includes by reference. One commit changes a component at most once. What a component's value means stays the caller's: the committer and every receiver compute it with the same
  function the caller gives. The feature turns on openmls's `extensions-draft`, under which openmls also marks a
  last-resort KeyPackage with an app data dictionary component instead of the `last_resort` extension.
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
