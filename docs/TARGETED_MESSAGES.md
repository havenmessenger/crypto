# MLS targeted messages

`crypto_core::mls::targeted` implements
[`draft-ietf-mls-targeted-messages-01`](https://datatracker.ietf.org/doc/draft-ietf-mls-targeted-messages/01/):
a message from one member of an MLS group to exactly one other member, that no third member of the
group can read.

## What a targeted message is

- The payload is encrypted with HPKE in **PSK mode** (RFC 9180 section 5.1.2) to the recipient's leaf
  encryption key. The pre-shared key is exported from the epoch's key schedule with the MLS-Exporter
  (`"targeted message"`, `"psk"`), so the ciphertext is bound to one group and one epoch.
- The sender **signs** the message (`SignWithLabel`, label `"TargetedMessageTBS"`) with the signature key
  of its leaf. The signature covers the group, epoch, recipient, authenticated data, sender, HPKE
  encapsulation and a hash of the ciphertext.
- The sender's leaf index, signature and HPKE encapsulation travel **encrypted** under a second
  exporter-derived secret, keyed by a sample of the ciphertext. A party outside the group learns
  neither who sent the message nor to whom it was sent beyond what the delivery path already reveals;
  other members of the group can learn the sender.
- `authenticated_data` is carried in the clear and authenticated.
- The content is followed by zero padding chosen by the sender; a receiver rejects any non-zero
  padding byte.

## API

```rust
use crypto_core::mls::targeted::{open, seal};

// Sender: a member of `group` in its current epoch.
let envelope: Vec<u8> = seal(&provider, &group, &signer, recipient_leaf, authenticated_data, payload, padding_len)?;

// Recipient: a different member of the same group, in the same epoch.
let opened = open(&provider, &group, &envelope)?;
// opened.sender_leaf_index, opened.authenticated_data, opened.application_data
```

`seal` and `open` take the openmls `MlsGroup` and provider the member already holds. All algorithms
come from the group's ciphersuite through `suite_policy::targeted_message_suite`, which applies the
same accept-gate as every other inbound MLS object.

## Validation order

`open` follows section 7 of the draft, step by step, and returns a distinct typed refusal for each step:

1. envelope version, then group;
2. **current epoch only** - a message for any other epoch is refused, and nothing is retained for past epochs;
3. the recipient leaf index is this member's own;
4. decrypt the sender data, and check the sender's leaf is not blank;
5. **verify the signature** - this happens before any content decryption;
6. decrypt the content with HPKE;
7. check that the padding is all zero.

Nothing is released to the caller unless every step passed. No error, `Debug` output or log line carries
key material or content.

## The versioned envelope

The draft sends a targeted message as an `MLSMessage` with a new `mls_targeted_message` wire format, whose
codepoint (0x0006) is only *suggested*. This library does not emit an `MLSMessage`. `seal` returns

```text
struct {
    uint16 draft_version;              // 1 = draft-ietf-mls-targeted-messages-01
    opaque targeted_message<V>;        // the serialized TargetedMessage of the draft
} Envelope;
```

`draft_version` names the draft revision the inner bytes follow. `open` refuses a version it does not
implement before it reads the body, and refuses trailing bytes. The suggested wire-format value is part
of the signed bytes, so a later revision of the draft, or an assigned codepoint that differs, is a **new
`draft_version`** rather than a change to version 1. When the draft becomes an RFC, the RFC framing is
added alongside and this one is retired deliberately.

## What it does not give

- **No replay protection.** A captured message is valid for the rest of its epoch. An application that
  needs replay detection puts a unique value in `authenticated_data` and remembers the values it has seen.
- **Epoch-granular forward secrecy.** The content is encrypted to the recipient's leaf key with no
  per-message key. Compromise of that leaf key within the epoch exposes the epoch's targeted messages;
  advancing the epoch and deleting the old key limits it.
- **Sender identity is hidden from outsiders, not from other members**, who hold the exporter secret.

## The recipient's leaf key

openmls keeps the private half of a leaf encryption key private to itself; the supported way to reach
it is the storage provider. `mls::targeted::leaf_key` reads the stored key pair through openmls's
storage traits into a private, read-only mirror of the stored layout (it cannot be serialized back), uses
it for one HPKE open, and wipes it. No public function returns it. The mirror follows the layout used
with openmls 0.8.1; tests pin that version and round-trip a real key, so an upgrade or layout change fails
loudly and forces a review.

## Test evidence

- The labelled primitives (`ExpandWithLabel`, `SignWithLabel`) are checked against the RFC 9420 crypto-basics
  test vectors (`src/mls/targeted/testdata/rfc9420_crypto_basics.json`, source named in the file).
- `stored_message_v1.json` holds a sealed message and both members' stored group state. A later change must
  still open it, and must still produce exactly these bytes when the HPKE ephemeral randomness is fixed to
  the stored seed (the seed hook exists only in test builds).
- Every refusal above has a test, and the tests that refuse before the signature is checked assert that no
  content decryption was attempted.
