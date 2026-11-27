# Changelog

This crate uses 0.x semantic versions: a minor version changes the public API or a wire format, a patch changes
anything else. There is no API-stability guarantee before 1.0 (see the README).

## Unreleased

- A `virtual-clients` feature, off by default, turning on openmls's virtual-clients draft (and `mimi-app-data`, since
  the draft needs openmls's extensions draft). Under the draft openmls creates every message and commit unconfirmed
  and offers no call that sends without that step, so with the feature each of this crate's sends and commits is
  confirmed as it is created (`mls::single_sender`), keeping no secret beyond the call. That is what a build without
  the feature does, and it is correct while exactly one emulator sends for each virtual-client leaf; an application
  with several sending emulators per leaf must confirm only after the delivery service accepts. A build without the
  feature is unchanged: its sends are openmls's own methods, and CI checks that it turns on none of the draft, and
  that no library build turns on openmls's `test-utils`, which the crate's tests use. Commit refusals caused by the
  draft (`VirtualClientsError`, `MalformedVcCommitData`, a derivation epoch that does not register) map to `Other`.
- For a consumer that turns on `did-webvh`: the `[patch]` that takes `jmap-did-types` from crates.io applies only
  where this crate is the workspace root. A workspace that depends on this crate and turns the feature on needs the
  same `[patch."https://github.com/MarkAtwood/crate-jmap"]` entry in its own root manifest, or that crate comes from
  its git repository.

- A `did-webvh` feature, off by default: it brings in `mls-didwebvh`, the reference crate of the did_webvh MLS
  credential (draft-atwood-mls-didwebvh-credential), for its log verification and group rules, and turns on
  `mimi-app-data`, where those rules keep their record. Nothing uses it yet. The crate is taken from its repository at
  one exact revision, the revision the interop hub uses, so a client and a hub validate a credential the same way; its
  did:webvh verifier comes from its crates.io release. A build without the feature carries none of it, which CI checks.
  The manifest-purity guard allows that one crate from that repository, and now also refuses a second revision of
  OpenMLS or of `mls-didwebvh`. `serde`, `serde_json` and `thiserror` move to the patch releases the crate requires.

- A member's renewed leaf keeps its credential identity (RFC 9420 §5.3.1, a valid successor). The commit receive paths
  (`mls::groups::mls_process_commit`, `mimi::mls_process_commit_appsync` and its variants, and
  `mimi::app_data::mimi_process_commit_app_data`) refuse a commit, before it is merged, whose UpdatePath leaf, or an
  Update proposal's leaf, carries another identity than the leaf it replaces: both must be Basic credentials with the
  same identity bytes. The refusal is a `CommitRefusal` with reason `Credential`, and the caller's state is unchanged. A
  signing-key rotation keeps the identity and is taken as before.
- `mimi::prepare_welcome_pinned` with `ExternalSendersPin`: a Welcome join that states what the joined group's external
  senders must be. With `NoExternalSenders`, a group naming any external sender is refused after the spend
  (`MimiWelcomeError::Spent`), so no party the joiner did not configure gets an external sender's standing; with `Hub`, it
  must name exactly that hub. `prepare_welcome_retirement` is unchanged: an empty hub key leaves them unchecked.
- `mimi::app_data::mimi_commit_app_data_bundle`: a MIMI commit with what the room's hub takes beside it
  (draft-ietf-mimi-protocol §5.3 `HandshakeBundle`): the bare Welcome for added members, the committer-signed
  `GroupInfo` for the epoch after the commit (TLS, no `MLSMessage` wrap), and the ratchet tree after it, from which a hub
  that does not yet track the room's tree starts tracking it. The `GroupInfo` carries the external public key, as
  openmls puts in every `GroupInfo` it exports. `mimi_commit_app_data_pending` is the same commit without them; its
  output is unchanged.
- `hpke-rs` 0.8 (from 0.7), the version openmls builds on, so the crate links one HPKE stack. Targeted messages and
  the reader seal build their HPKE context with `try_new`: if the system's randomness can't be had, the operation is
  refused with its usual error instead of panicking. Their wire output is unchanged; the stored vectors still match
  byte for byte.
- `mls::rotation::rotate_signer_pending`: a member stages one commit that renews its leaf and replaces its signing key
  with a new bundle's key, so that once the group has processed it every member verifies the member's messages under
  the new key and refuses the old one. The commit is signed with the current key (receivers verify a commit against the
  committer's leaf as it stood); the caller opens the group with the new bundle once the commit is accepted. A new
  bundle naming another user, with another signature scheme than the group's, carrying the key the leaf already holds,
  or holding a private key that does not sign for its public key (checked with a probe signature) is refused before
  anything is staged. `leaf_uses_bundle` tells from a group state whether the member's leaf already carries a bundle's
  signing key; the bundle's private key is wiped when it returns.
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
