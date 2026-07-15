//! A runnable walkthrough of this crate's `OpenPGP` surface: `cargo run --example pgp_roundtrip`.
//!
//! Two parties, Alice and Bob, each generate a keypair, then Alice sends Bob a signed and
//! encrypted message. Bob decrypts and verifies it with the strict (authenticated) API, which
//! fails closed on anything unsigned or wrong-signer rather than returning a plaintext the
//! caller has to remember to check. This is real key generation and real `OpenPGP` encryption,
//! not a mock; every call below is the same public API the client calls.
//!
//! `unwrap`/`expect` are fine here (narrative demo code, not the library) - the crate's own
//! `unwrap_used` clippy lint applies to the `--lib` surface only, which examples are outside of.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crypto_core::pgp::{pgp_decrypt_and_verify_strict_impl, pgp_generate_key, pgp_sign_and_encrypt};

fn main() {
    let (alice_pub, alice_priv) = pgp_generate_key(
        "Alice".into(),
        "alice@example.com".into(),
        "alice-passphrase".into(),
        "ecc".into(),
    )
    .expect("Alice's key generation");

    let (bob_pub, bob_priv) = pgp_generate_key(
        "Bob".into(),
        "bob@example.com".into(),
        "bob-passphrase".into(),
        "ecc".into(),
    )
    .expect("Bob's key generation");

    println!("Generated two ECC (Curve25519) keypairs.");

    let plaintext = "Meet at the usual place, same time.";
    let encrypted = pgp_sign_and_encrypt(
        plaintext.into(),
        bob_pub,
        alice_priv,
        "alice-passphrase".into(),
    )
    .expect("sign and encrypt");

    println!("Alice signed and encrypted a message to Bob ({} bytes armored).", encrypted.len());

    let recovered = pgp_decrypt_and_verify_strict_impl(
        encrypted,
        bob_priv,
        "bob-passphrase".into(),
        alice_pub,
    )
    .expect("decrypt and verify");

    assert_eq!(recovered, plaintext);
    println!("Bob decrypted and verified the message: \"{recovered}\"");
    println!(
        "The strict API returned the plaintext only because the signature checked out against \
         Alice's public key. A wrong signer or a stripped signature would return Err instead of \
         a plaintext the caller has to remember to gate on a boolean."
    );
}
