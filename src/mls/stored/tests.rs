#![allow(deprecated)] // the byte-in/byte-out functions are the oracle these tests compare against

use std::sync::Mutex;

use super::*;
use crate::identity::generate_identity;
use crate::mls::store::{export_state_v1, import_state, MemoryMlsStore, MlsStoreError};

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_secs() as i64
}

/// A store that records the writes an operation makes.
struct Counting {
    inner: MemoryMlsStore,
    puts: Mutex<Vec<Vec<u8>>>,
    deletes: Mutex<Vec<Vec<u8>>>,
    fail_puts: bool,
}

impl Counting {
    fn new() -> Self {
        Self {
            inner: MemoryMlsStore::new(),
            puts: Mutex::default(),
            deletes: Mutex::default(),
            fail_puts: false,
        }
    }
    fn reset(&self) {
        self.puts.lock().unwrap().clear();
        self.deletes.lock().unwrap().clear();
    }
    fn written(&self) -> (usize, usize) {
        (
            self.puts.lock().unwrap().len(),
            self.deletes.lock().unwrap().len(),
        )
    }
    fn put_labels(&self) -> Vec<String> {
        self.puts
            .lock()
            .unwrap()
            .iter()
            .map(|key| {
                let end = key
                    .iter()
                    .position(|b| !b.is_ascii_alphabetic())
                    .unwrap_or(key.len());
                String::from_utf8_lossy(&key[..end]).into_owned()
            })
            .collect()
    }
}

impl MlsStore for Counting {
    fn get(&self, group: &[u8], key: &[u8]) -> Result<Option<Vec<u8>>, MlsStoreError> {
        self.inner.get(group, key)
    }
    fn put(&self, group: &[u8], key: &[u8], value: &[u8]) -> Result<(), MlsStoreError> {
        if self.fail_puts {
            return Err(MlsStoreError::Backend("disk full".into()));
        }
        self.puts.lock().unwrap().push(key.to_vec());
        self.inner.put(group, key, value)
    }
    fn delete(&self, group: &[u8], key: &[u8]) -> Result<(), MlsStoreError> {
        self.deletes.lock().unwrap().push(key.to_vec());
        self.inner.delete(group, key)
    }
    fn keys(&self, group: &[u8]) -> Result<Vec<Vec<u8>>, MlsStoreError> {
        self.inner.keys(group)
    }
}

struct Pair {
    alice_store: Counting,
    alice: Vec<u8>,
    bob_store: Counting,
    bob: Vec<u8>,
}

/// Alice makes a group, adds Bob, and Bob joins: both ends hold the group in their own store.
fn pair() -> Pair {
    let (_, _, alice) = generate_identity("alice".into(), now()).unwrap();
    let (_, bob_package, bob) = generate_identity("bob".into(), now()).unwrap();
    let alice_store = Counting::new();
    create_group(&alice_store, "stored-test", &alice).unwrap();
    let (welcome, _commit) =
        add_member(&alice_store, b"stored-test", &alice, &bob_package).unwrap();
    let bob_store = Counting::new();
    let (group, bob) = process_welcome(&bob_store, &welcome, &bob).unwrap();
    assert_eq!(group, b"stored-test");
    Pair {
        alice_store,
        alice,
        bob_store,
        bob,
    }
}

#[test]
fn a_group_made_and_joined_through_stores_sends_and_receives() {
    let p = pair();
    let ciphertext =
        encrypt_message(&p.alice_store, b"stored-test", &p.alice, b"hello bob").unwrap();
    let (plaintext, sender) =
        decrypt_message(&p.bob_store, b"stored-test", &p.bob, &ciphertext).unwrap();
    assert_eq!(plaintext, b"hello bob");
    assert_eq!(sender.group_id, b"stored-test");
    let members = list_members(&p.bob_store, b"stored-test").unwrap();
    assert_eq!(members.len(), 2, "alice and bob: {members:?}");
    assert_eq!(
        members.len(),
        list_members_with_indices(&p.alice_store, b"stored-test")
            .unwrap()
            .len()
    );
    assert_eq!(
        inspect_group(&p.alice_store, b"stored-test").unwrap().epoch,
        1
    );
}

#[test]
fn one_message_writes_exactly_one_entry_and_deletes_none() {
    let p = pair();
    p.alice_store.reset();
    p.bob_store.reset();
    let ciphertext =
        encrypt_message(&p.alice_store, b"stored-test", &p.alice, b"just one").unwrap();
    assert_eq!(
        p.alice_store.written(),
        (1, 0),
        "sending changes one entry: {:?}",
        p.alice_store.put_labels()
    );
    assert_eq!(
        p.alice_store.put_labels(),
        vec!["MessageSecrets".to_string()]
    );
    decrypt_message(&p.bob_store, b"stored-test", &p.bob, &ciphertext).unwrap();
    assert_eq!(
        p.bob_store.written(),
        (1, 0),
        "receiving changes one entry: {:?}",
        p.bob_store.put_labels()
    );
}

#[test]
fn a_membership_change_rewrites_the_tree_and_the_epoch_and_nothing_that_did_not_change() {
    let p = pair();
    let (_, carol_package, _) = generate_identity("carol".into(), now()).unwrap();
    let entries_before = p.alice_store.inner.entries(b"stored-test").len();
    p.alice_store.reset();
    add_member(&p.alice_store, b"stored-test", &p.alice, &carol_package).unwrap();
    let labels = p.alice_store.put_labels();
    assert!(
        labels.iter().any(|l| l == "Tree"),
        "an add rewrites the tree: {labels:?}"
    );
    assert!(
        labels.len() < entries_before + 4,
        "an add writes the entries it changed, not a whole group of {entries_before}: {labels:?}"
    );
}

#[test]
fn an_operation_that_fails_writes_nothing() {
    let p = pair();
    p.alice_store.reset();
    p.bob_store.reset();
    assert!(decrypt_message(&p.bob_store, b"stored-test", &p.bob, b"not a ciphertext").is_err());
    assert!(add_member(
        &p.alice_store,
        b"stored-test",
        &p.alice,
        b"not a key package"
    )
    .is_err());
    assert!(mls_process_commit(&p.bob_store, b"stored-test", &p.bob, b"not a commit").is_err());
    assert_eq!(p.alice_store.written(), (0, 0));
    assert_eq!(p.bob_store.written(), (0, 0));
}

#[test]
fn an_operation_on_a_group_the_store_does_not_hold_is_refused() {
    let store = MemoryMlsStore::new();
    let (_, _, alice) = generate_identity("alice".into(), now()).unwrap();
    assert!(encrypt_message(&store, b"nobody", &alice, b"x").is_err());
    assert!(list_members(&store, b"nobody").is_err());
}

#[test]
fn a_store_that_cannot_write_fails_the_operation_loudly() {
    let (_, _, alice) = generate_identity("alice".into(), now()).unwrap();
    let mut store = Counting::new();
    store.fail_puts = true;
    let error = create_group(&store, "stored-test", &alice).unwrap_err();
    assert!(error.to_string().contains("disk full"), "{error}");
}

#[test]
fn the_older_byte_functions_and_the_store_functions_work_on_one_group() {
    // A group started by the byte-in/byte-out functions is imported and continued through a store.
    let (_, _, alice) = generate_identity("alice".into(), now()).unwrap();
    let (_, bob_package, bob) = generate_identity("bob".into(), now()).unwrap();
    let state = groups::create_group("mixed".into(), alice.clone()).unwrap();
    let (state, welcome, _) = groups::add_member(state, alice.clone(), bob_package).unwrap();
    let store = MemoryMlsStore::new();
    import_state(&store, &state).unwrap();
    let (bob_state, _) = groups::process_welcome(welcome, bob.clone()).unwrap();
    let ciphertext = encrypt_message(&store, b"mixed", &alice, b"from the store").unwrap();
    let (_, plaintext, _) = groups::decrypt_message(bob_state, bob, ciphertext).unwrap();
    assert_eq!(plaintext, b"from the store");

    // And back: a store group exported in either form is a state the older functions accept.
    let v1 = export_state_v1(&store, b"mixed").unwrap();
    let again = groups::encrypt_message(v1.to_vec(), alice.clone(), b"back".to_vec());
    assert!(again.is_ok());
    let v2 = crate::mls::store::export_state_v2(&store, b"mixed").unwrap();
    let from_v2 = MemoryMlsStore::from_state(&v2).unwrap();
    assert!(encrypt_message(&from_v2, b"mixed", &alice, b"from v2").is_ok());
}

#[test]
fn a_mimi_group_is_made_and_listed_through_a_store() {
    let (_, _, alice) = crate::mimi::mimi_generate_identity("alice".into(), now()).unwrap();
    let store = MemoryMlsStore::new();
    mimi_create_group(&store, "mimi-stored", &alice).unwrap();
    assert_eq!(list_members(&store, b"mimi-stored").unwrap().len(), 1);
}
