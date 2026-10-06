#![allow(deprecated)] // the byte-in/byte-out functions are the oracle these tests compare against

use super::*;
use crate::identity::generate_identity;
use crate::mls::groups::{add_member, create_group};

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_secs() as i64
}

/// A real two-member group's state, in the byte form the older functions return.
fn real_state() -> Vec<u8> {
    let (_, _, alice) = generate_identity("alice".into(), now()).unwrap();
    let (_, bob_package, _) = generate_identity("bob".into(), now()).unwrap();
    let state = create_group("store-test".into(), alice.clone()).unwrap();
    add_member(state, alice, bob_package).unwrap().0
}

#[test]
fn a_memory_store_keeps_groups_apart_and_deleting_an_absent_key_succeeds() {
    let store = MemoryMlsStore::new();
    store.put(b"g1", b"k", b"one").unwrap();
    store.put(b"g2", b"k", b"two").unwrap();
    assert_eq!(
        store.get(b"g1", b"k").unwrap().as_deref(),
        Some(&b"one"[..])
    );
    assert_eq!(
        store.get(b"g2", b"k").unwrap().as_deref(),
        Some(&b"two"[..])
    );
    assert_eq!(store.get(b"g1", b"other").unwrap(), None);
    store.delete(b"g1", b"absent").unwrap();
    store.delete(b"nobody", b"k").unwrap();
    store.delete(b"g1", b"k").unwrap();
    assert!(store.keys(b"g1").unwrap().is_empty());
    assert_eq!(store.keys(b"g2").unwrap(), vec![b"k".to_vec()]);
}

#[test]
fn a_snapshot_in_either_form_imports_to_the_same_entries() {
    let v1 = real_state();
    let from_v1 = MemoryMlsStore::from_state(&v1).unwrap();
    let group = b"store-test";
    let entries = from_v1.entries(group);
    assert!(!entries.is_empty());

    let v2 = from_v1.to_state_v2(group).unwrap();
    assert!(v2.starts_with(b"MLSS\x02"));
    let from_v2 = MemoryMlsStore::from_state(&v2).unwrap();
    assert_eq!(
        from_v2.entries(group),
        entries,
        "binary form must hold the same entries"
    );

    let back_to_v1 = from_v2.to_state_v1(group).unwrap();
    let again = MemoryMlsStore::from_state(&back_to_v1).unwrap();
    assert_eq!(
        again.entries(group),
        entries,
        "json form must hold the same entries"
    );
}

#[test]
fn the_binary_snapshot_is_under_a_third_the_size_of_the_json_one() {
    let v1 = real_state();
    let store = MemoryMlsStore::from_state(&v1).unwrap();
    let v2 = store.to_state_v2(b"store-test").unwrap();
    assert!(
        v1.len() >= v2.len() * 5,
        "json {} bytes, binary {} bytes: expected at least 5x",
        v1.len(),
        v2.len()
    );
}

#[test]
fn a_damaged_or_unknown_snapshot_is_refused_not_guessed() {
    let store = MemoryMlsStore::new();
    assert!(import_state(&store, b"").is_err());
    assert!(import_state(&store, b"MLSS\x02\xff\xff\xff").is_err());
    assert!(import_state(&store, b"MLSS\x09whatever").is_err());
    assert!(import_state(&store, b"{\"group_id\": 7}").is_err());
    assert!(
        store.keys(b"store-test").unwrap().is_empty(),
        "a refused snapshot wrote nothing"
    );
}

#[test]
fn importing_a_snapshot_replaces_the_groups_entries() {
    let store = MemoryMlsStore::new();
    store.put(b"store-test", b"stale", b"entry").unwrap();
    import_state(&store, &real_state()).unwrap();
    assert_eq!(store.get(b"store-test", b"stale").unwrap(), None);
}

#[test]
fn applying_a_change_touches_only_what_differs() {
    let store = MemoryMlsStore::new();
    let before: BTreeMap<Vec<u8>, Vec<u8>> = [
        (b"a".to_vec(), b"1".to_vec()),
        (b"b".to_vec(), b"2".to_vec()),
        (b"c".to_vec(), b"3".to_vec()),
    ]
    .into();
    for (k, v) in &before {
        store.put(b"g", k, v).unwrap();
    }
    let after: BTreeMap<Vec<u8>, Vec<u8>> = [
        (b"a".to_vec(), b"1".to_vec()),
        (b"b".to_vec(), b"22".to_vec()),
        (b"d".to_vec(), b"4".to_vec()),
    ]
    .into();
    assert_eq!(apply_change(&store, b"g", &before, &after).unwrap(), (2, 1));
    assert_eq!(read_entries(&store, b"g").unwrap(), after);
}
