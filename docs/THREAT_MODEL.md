# Threat Model - Haven Crypto

> This document is the basis for the independent third-party security audit
> (NLnet-sponsored, via Radically Open Security). It states what this crate protects,
> against whom, what it does not protect, and where the residual risks are.

## The claim being defended
Only the sender and intended recipients can read message content. Haven's operators cannot.

## Trust assumptions
- **The server is untrusted.** It stores and routes ciphertext; it never holds plaintext or
  usable private keys.
- **The user's device is trusted** while unlocked. At-rest protection guards a locked/stolen
  device (handled by the client's encrypted storage).

## In scope
- Confidentiality + integrity of message content.
- Key generation, handling, and lifecycle within this crate.

## Out of scope (here)
- Server/infrastructure compromise (closed-source, separate process).
- Endpoint compromise (malware on an unlocked device).
- Metadata minimization. This crate encrypts message **content**, not envelope metadata. For
  email (PGP/MIME, RFC-3156) the **Subject and routing headers travel in cleartext** so mail can
  be delivered; any hop can see them. In-app (MLS) messaging encrypts content fully.

## Adversaries considered

### Network adversary (passive or active, on the wire)
**Capability assumed:** can observe and tamper with every byte this crate's output travels in.
**Mitigation:** the two protocols this crate produces reach integrity by different, both
fail-closed, mechanisms - **MLS** application messages are true AEAD (AES-128-GCM under the
pinned ciphersuite): a passive observer gets only ciphertext, and any tampering is caught by the
authentication tag before plaintext is ever returned. **OpenPGP** messages use SEIPDv1
(`encrypt_to_keys_seipdv1`/`encrypt_with_password_seipdv1`) - a modification-detection code (MDC)
inside the encrypted stream, not an AEAD construction with an associated-data-bound tag. rPGP
still rejects a corrupted SEIPDv1 packet closed (verified by this crate's own tamper tests), so
the fail-closed PROPERTY holds for both protocols; the MECHANISM differs. This crate does not
itself open network sockets or perform TLS; it has no opinion on transport-layer confidentiality,
only on what travels over that transport.
**Residual:** this crate encrypts message *content*, not envelope metadata - see "Out of
scope" above for the email Subject/routing-header disclosure.

### Malicious or compromised server
**Capability assumed:** full read access to everything a Haven server stores and processes.
**Mitigation:** private key material this crate custodies is never handed to a server in usable
form - identity private keys are stored as passphrase-protected OpenPGP armor, and a
session's derived root key lives only in this crate's own zeroize-on-drop, in-process store
(never persisted, never serialized to a caller in raw form). A server holding every blob this
crate ever produces still cannot derive a usable secret key without the user's passphrase.
**Residual:** a server sees ciphertext and (for email) routing metadata by protocol necessity;
it is a design goal that this is *all* it ever sees, not that it sees nothing.

### Lost or stolen device (locked)
**Capability assumed:** physical possession of a locked device.
**Mitigation:** within this crate's own boundary, no secret persists across process restarts, and
this crate performs no disk I/O of its own. The custody store (`secret_store::SessionSecrets`,
holding the session root key + cached HKDF subkeys + the PGP identity) derives `ZeroizeOnDrop` and
is wiped whenever `lock`/`lock_all` runs or the process tears the registry down - including a
SECOND `set_pgp_identity` call, which zeroizes the outgoing value before replacing it, not just the
final one. The MLS-op value types (`GroupState`, `IdentityBundle`) wipe their OWN deserialized
struct fields (a manual `Drop` impl) for the duration this crate holds them as a live struct.
**Precise boundary (do not read this as broader than it is):** this covers what this crate holds
as a *live, in-scope struct or custody entry*. It does NOT cover (a) the *serialized* `Vec<u8>`
wire forms of `GroupState`/`IdentityBundle` (`bundle_bytes`/`state_bytes`) once returned across the
FRB boundary - those become the caller's (the client application's) storage responsibility the
moment this crate hands them back, same as any other returned buffer; (b) `openmls`'s own
`MemoryStorage` internal copy inside the per-operation `OpenMlsRustCrypto` provider, which this
crate does not control and does not zeroize (each provider is freshly constructed per call and
discarded, not a long-lived process, but `openmls` does not wipe its own storage on drop). Full
at-rest protection for a *locked* device (the device's own disk/database encryption) is a
client-application concern, deliberately out of this crate's scope (see "Out of scope" above) -
this crate's contribution is bounded to the custody store + its own in-scope struct lifetimes, not
every byte that transits it.
**Residual:** an *unlocked* device is explicitly a trusted-device scenario throughout this
document (see "Trust assumptions"); this crate makes no claim against that adversary.

**Current state:** every production call site in `crate::mls::groups` and `crate::mimi` routes
both the deserialized owned bytes it takes in (`group_state_bytes`/`bundle_bytes`) and the
serialized bytes it returns through `Zeroizing` (`zeroizing_json`), so within this crate's own
process, before either buffer crosses the FRB boundary, it wipes on drop rather than sitting
unwiped. Two residuals remain, disclosed rather than closed:
- **Reallocation and error-path gap.** `zeroizing_json` wraps only the buffer `serde_json::
  to_vec` hands back. Growing that buffer during serialization reallocates and frees each
  earlier, smaller backing buffer unwiped, and a serialization error drops the partially-written
  internal buffer before it ever reaches `Zeroizing::new`. Both happen inside `serde_json::
  to_vec`'s own call frame. Open item: a custom `serde_json::to_writer` sink writing into a
  buffer this crate owns and wipes could close it.
- **Construction, not convention.** `GroupState` and `IdentityBundle` carry no `Serialize`/
  `Deserialize` implementation of their own. The only way to reach their wire form is the
  inherent `to_zeroizing_json`/`from_slice` pair, which routes every serialize through
  `zeroizing_json` over a module-private DTO - a caller cannot obtain an unwiped buffer with
  `serde_json::to_vec` or any other `Serialize`-based encoder, because neither type implements
  the trait those encoders require. This is a type-level guarantee, not a call-site convention:
  the compiler rejects a bypass attempt at build time. Compat note: this removed the types'
  public `Serialize`/`Deserialize` derive, an API break for any external consumer constructing
  or encoding these types directly - none exists today (every current call site is internal to
  this crate; the FRB boundary in the consuming client passes raw `Vec<u8>`, never these Rust
  types).

### A tampered legacy-format blob
**Capability assumed:** the ability to modify a blob previously encrypted in this crate's
legacy CTR+PKCS7 format (`crypto::aes_ctr_256_pkcs7_open`), before it is read back on a
fresh-device restore.
**Mitigation:** this reader exists only to keep already-encrypted MLS-identity backup and
contact-history blobs decryptable across a migration from the CTR+PKCS7 format this crate no
longer writes. It is decrypt-only, never used for new writes, and only ever reads a blob the
caller's own storage already holds - not network input. It is fail-closed on malformed PKCS7
padding (never returns truncated plaintext), but CTR is a stream cipher with no integrity tag,
so a bit-flip in the ciphertext produces a corresponding bit-flip in the recovered plaintext
that this function cannot detect.
**Residual:** an attacker who can tamper with this specific at-rest blob between write and
read gets undetected plaintext corruption on that blob, unlike every other read path in this
crate (which is AEAD or MDC-protected). Planned retirement: a re-encrypt-on-read migration that
replaces each such blob with an AES-GCM one on first successful decrypt, after which this
reader has no remaining callers.

### Supply-chain
**Capability assumed:** a compromised or vulnerable upstream dependency.
**Mitigation:** no hand-rolled cryptography anywhere in this crate - every primitive composes
vetted, independently-maintained crates (RustCrypto's AES/HKDF/PBKDF2/HMAC family, `dalek`
Ed25519, `rPGP`, `openmls`), all sourced from crates.io with no vendored or forked copies.
Every cryptographic operation is gated by known-answer tests against published RFC/NIST test
vectors, so a dependency regression that silently changed output would fail the test suite, not
ship silently. `cargo audit` runs in CI against the full dependency tree; every currently-ignored
advisory has a written, reasoned disposition in `.cargo/audit.toml` (reachability traced against
the actual call graph, not assumed away).
**Residual:** a disposition in `.cargo/audit.toml` is only as good as the reasoning behind it -
each one is re-evaluated whenever the dependency graph that produced it changes.
