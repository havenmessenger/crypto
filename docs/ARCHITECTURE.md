# Architecture - Haven Crypto

## Purpose
This crate is the cryptographic core consumed by the Haven client. It exposes OpenPGP and
MLS-related primitives over a stable API, compiled to both native targets and WebAssembly
(for the web client).

## Design principles
- **Composition over invention.** Vetted primitives only; no bespoke ciphers.
- **Keys are caller-owned.** This crate operates on keys; it does not silently persist them.
  Key *storage* (encrypted, on-device) is the client's responsibility.
- **Deterministic + testable.** Known-answer tests gate cryptographic behavior.

## Boundary (open vs. closed)
This crate (open) performs encryption/decryption and key operations on the device. Haven's
servers (closed) handle encrypted message bodies + attachments and never see plaintext content
or usable private keys. (For email, the Subject and routing headers are necessarily cleartext -
this crate encrypts content, not envelope metadata; see [`THREAT_MODEL.md`](THREAT_MODEL.md).)

## Module map
| Module | Contents |
|---|---|
| `crypto` | PBKDF2-HMAC-SHA256, AES-256-GCM (incl. a 16-byte-IV variant, both keyed through the typed `Key32` newtype), AES-256-CTR (legacy read), HKDF-SHA256, BIP-39 mnemonic (entropy/phrase, no seed derivation), a generic secure-random-bytes primitive, and HMAC-SHA256. Every primitive has a known-answer test against a published RFC/NIST vector. |
| `crypto::compat` | Constrained primitives kept for byte-compatibility with an existing wire format, not for new use: caller-nonce AES-GCM (nonce uniqueness is the caller's responsibility) and raw AES-CTR (no authentication). Reaching into this module is a visible, explicit decision - no other function in this crate calls into it. (A separate, main-surface function, `crypto::aes_ctr_256_pkcs7_open`, is its own unauthenticated legacy CTR reader over a different wire format - see `THREAT_MODEL.md`.) |
| `pgp` | OpenPGP (RFC 4880) key generation, encryption/decryption (asymmetric + symmetric), signing/verification, cross-signing for key rotation, and HD-deterministic key derivation from a 32-byte seed (so an identity is recoverable from the seed phrase alone). |
| `mls` / `mls::groups` | MLS (RFC 9420) group lifecycle: create, encrypt/decrypt, add/remove members, process Welcome/Commit messages, key-package regeneration. |
| `identity` | Identity bundle generation (native + seed-derived), including the HD-deterministic MLS signing key. |
| `mimi` | MIMI-over-MLS integration: group operations mirrored for the federation/interop surface, plus AppSync capability negotiation. |
| `mime` | A fail-closed, depth-capped, never-panics parser for decrypted inner-MIME payloads (untrusted input), and an RFC-3156 §4 PGP/MIME envelope + full outer-message builder. |
| `secret_store` | A handle-based, `Zeroize`-backed session secret custodian - the caller hands in an already-derived root key once and receives an opaque handle; the raw key never crosses back out. |
| `suite_policy` | The crypto-agility seam: the single place that names which ciphersuite/algorithm this crate *generates* with, and which inbound MLS ciphersuites it *accepts* - so a future suite (e.g. post-quantum) is a change here, not a scattered wire-format hunt. |

## Enforcement direction
Most of this crate's functions are free functions over caller-supplied bytes: correctness lives
in the implementation, but call ordering and result-handling are the caller's responsibility (a
decrypt-and-verify result the caller can destructure and ignore the validity flag; a serialized
group state the caller could replay out of order). This is the current shape, not the intended
one. The API is moving toward types that make misuse unrepresentable rather than merely
documented:

- A profile-scoped context becomes the sole entry point to protocol operations, so an operation a
  profile forbids is not a method that exists to call, not a runtime check a caller can skip.
- Group state becomes a state-owning handle with a monotonic epoch/CAS guard, not a byte buffer a
  caller can copy, mutate, and hand back out of order.
- Secret custody types keep no path to plaintext bytes outside an explicit legacy module.
- Decrypt/verify operations gain a typed result that only unwraps to plaintext after verification
  passed, alongside (not replacing) the existing tuple-returning form.

Changes toward this shape land incrementally and additively; the free-function surface documented
above stays available throughout.

## What this crate deliberately does NOT do
No FRB/app-binding code, no network I/O, no persistent storage. The one exception worth
naming explicitly: `secret_store` holds secret material **in process memory** for the
lifetime of a caller-managed handle - that is custody, not storage; nothing here writes to
disk. Consumers (the Haven client) own key storage, UI, and the actual FRB boundary.
