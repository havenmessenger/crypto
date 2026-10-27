use super::{
    MessageDecryptionError, ProcessMessageError, ProcessingError, SecretTreeError, ValidationError,
};
use crate::identity::generate_identity;
use crate::mls::groups::{
    add_member, create_group, decrypt_message, encrypt_message, process_welcome,
};

/// Bob's group state once he has read one message from Alice, and that message.
fn bob_after_one_message() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("a clock after 1970")
        .as_secs()
        .try_into()
        .expect("a clock before 2262");
    let (_, _, alice) = generate_identity("alice".to_string(), now).expect("generate alice");
    let (_, bob_key_package, bob) =
        generate_identity("bob".to_string(), now).expect("generate bob");
    let group = create_group("processing-error".to_string(), alice.clone()).expect("create_group");
    let (group, welcome, _) =
        add_member(group, alice.clone(), bob_key_package).expect("add_member");
    let (bob_state, _) = process_welcome(welcome, bob.clone()).expect("process_welcome");
    let (_, ciphertext) = encrypt_message(group, alice, b"once".to_vec()).expect("encrypt_message");
    let (bob_state, _, _) =
        decrypt_message(bob_state, bob.clone(), ciphertext.clone()).expect("first decrypt");
    (bob_state, bob, ciphertext)
}

/// A message read twice is refused because its key was used, and the refusal is the MLS implementation's own value,
/// shown in the same words as before it was kept.
#[test]
fn a_refused_message_keeps_the_refusal_and_its_words() {
    let (bob_state, bob, ciphertext) = bob_after_one_message();
    let error = decrypt_message(bob_state, bob, ciphertext).expect_err("a used key");
    assert_eq!(
        "Processing error: ValidationError(UnableToDecrypt(SecretTreeError(SecretReuseError)))",
        error.to_string()
    );
    assert_eq!(
        error.to_string(),
        format!("{error:?}"),
        "Debug shows what Display does"
    );
    let refusal = error
        .downcast_ref::<ProcessingError>()
        .expect("the refusal is kept")
        .refusal();
    assert!(
        matches!(
            refusal,
            ProcessMessageError::ValidationError(ValidationError::UnableToDecrypt(
                MessageDecryptionError::SecretTreeError(SecretTreeError::SecretReuseError)
            ))
        ),
        "{refusal:?}"
    );
}

/// A message that never reached the MLS implementation is not one it refused.
#[test]
fn a_failure_before_processing_is_not_a_refusal() {
    let (bob_state, bob, _) = bob_after_one_message();
    let error = decrypt_message(bob_state, bob, vec![0xff; 8]).expect_err("not a message");
    assert!(error.downcast_ref::<ProcessingError>().is_none(), "{error}");
}
