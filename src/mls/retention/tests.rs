use crate::mls::{groups::*, GroupState, IdentityBundle, MlsSigner};
use openmls::prelude::*;
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::storage::StorageProvider;
use openmls_traits::OpenMlsProvider;
use tls_codec::Deserialize as _;
use zeroize::Zeroizing;

fn identity(name: &str, mimi: bool) -> (Vec<u8>, Vec<u8>) {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let (_, package, bundle) = if mimi {
        crate::mimi::mimi_generate_identity(name.into(), now).unwrap()
    } else {
        crate::identity::generate_identity(name.into(), now).unwrap()
    };
    (package, bundle)
}

fn export(provider: &OpenMlsRustCrypto, id: &GroupId) -> Vec<u8> {
    let state = GroupState {
        group_id: id.to_vec(),
        storage_map: provider
            .storage()
            .values
            .read()
            .unwrap()
            .clone()
            .into_iter()
            .collect(),
    };
    serde_json::to_vec(&state).unwrap()
}

fn zero_capacity_founder(bundle: &[u8], mimi: bool) -> Vec<u8> {
    let mut identity: IdentityBundle = serde_json::from_slice(bundle).unwrap();
    let provider = OpenMlsRustCrypto::default();
    let signer = MlsSigner {
        key: Zeroizing::new(std::mem::take(&mut identity.private_key)),
        scheme: identity.signature_scheme,
    };
    let credential = CredentialWithKey {
        credential: BasicCredential::new(identity.user_id.as_bytes().to_vec()).into(),
        signature_key: identity.public_key_bytes.clone().into(),
    };
    let mut builder = MlsGroupCreateConfig::builder()
        .ciphersuite(crate::suite_policy::mls_generation_suite())
        .max_past_epochs(0);
    if mimi {
        builder = builder
            .wire_format_policy(MIXED_PLAINTEXT_WIRE_FORMAT_POLICY)
            .use_ratchet_tree_extension(true)
            .capabilities(crate::mimi::mimi_appsync_capabilities());
    }
    let group = MlsGroup::new_with_group_id(
        &provider,
        &signer,
        &builder.build(),
        GroupId::from_slice(b"retention-room"),
        credential,
    )
    .unwrap();
    export(&provider, group.group_id())
}

fn zero_capacity_join(welcome: &[u8], bundle: &[u8], mimi: bool) -> Vec<u8> {
    let mut identity: IdentityBundle = serde_json::from_slice(bundle).unwrap();
    let provider = OpenMlsRustCrypto::default();
    *provider.storage().values.write().unwrap() = std::mem::take(&mut identity.storage_map)
        .into_iter()
        .collect();
    let (wire, tree) = if mimi {
        (welcome.to_vec(), None)
    } else {
        let (wire, tree): (Vec<u8>, Vec<u8>) = serde_json::from_slice(welcome).unwrap();
        (
            wire,
            Some(RatchetTreeIn::tls_deserialize_exact(&tree).unwrap()),
        )
    };
    let MlsMessageBodyIn::Welcome(welcome) = MlsMessageIn::tls_deserialize_exact(&wire)
        .unwrap()
        .extract()
    else {
        panic!("expected Welcome");
    };
    let mut builder = MlsGroupJoinConfig::builder().max_past_epochs(0);
    if mimi {
        builder = builder.wire_format_policy(MIXED_PLAINTEXT_WIRE_FORMAT_POLICY);
    }
    let group = StagedWelcome::new_from_welcome(&provider, &builder.build(), welcome, tree)
        .unwrap()
        .into_group(&provider)
        .unwrap();
    export(&provider, group.group_id())
}

fn add(
    state: Vec<u8>,
    bundle: Vec<u8>,
    package: Vec<u8>,
    mimi: bool,
) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    if mimi {
        crate::mimi::mimi_add_member_commit(state, bundle, package).unwrap()
    } else {
        add_member(state, bundle, package).unwrap()
    }
}

fn merge(state: Vec<u8>, bundle: Vec<u8>, commit: Vec<u8>, mimi: bool) -> Vec<u8> {
    if mimi {
        crate::mimi::mls_process_commit_appsync(state, bundle, commit)
            .unwrap()
            .0
    } else {
        mls_process_commit(state, bundle, commit).unwrap().0
    }
}

fn migrated(state: &[u8]) -> Vec<u8> {
    let result = super::migrate_group_retention_to_three(state);
    assert!(
        result.is_ok(),
        "legacy migration must return a validated coherent replacement: {:?}",
        result.as_ref().err()
    );
    result.unwrap().unwrap_or_else(|| state.to_vec())
}

#[test]
fn secret_store_contexts_and_retained_epoch_bounds_cannot_name_another_group() {
    let (_, alice) = identity("retention-alice", false);
    let base = migrated(&zero_capacity_founder(&alice, false));
    let other = create_group("another-retention-group".into(), alice.clone()).unwrap();
    let transplant = super::with_state(&other, |_, provider, group_id| {
        Ok(super::read_retention(provider, group_id)?.1)
    })
    .unwrap();
    let invalid = super::with_state(&base, |_, provider, group_id| {
        provider
            .0
            .storage()
            .write_message_secrets(group_id, &transplant)?;
        Ok(export(&provider.0, group_id))
    })
    .unwrap();
    assert!(
        super::inspect_group_retention(&invalid).is_err(),
        "a same-key secret store from another group is refused"
    );
    assert!(super::migrate_group_retention_to_three(&invalid).is_err());

    let (package, _) = identity("retention-extra", false);
    let (advanced, _, _) = add(base, alice, package, false);
    for mode in ["future", "too-old", "duplicate", "over-capacity"] {
        let invalid = super::with_state(&advanced, |_, provider, group_id| {
            let (metadata, mut store, _) = super::read_retention(provider, group_id)?;
            assert_eq!(store.past_epoch_trees.len(), 1);
            match mode {
                "future" => store.past_epoch_trees[0].epoch = metadata.epoch,
                "too-old" => store.past_epoch_trees[0].epoch = u64::MAX,
                "duplicate" => {
                    let copy = serde_json::from_slice(
                        &serde_json::to_vec(&store.past_epoch_trees[0]).unwrap(),
                    )
                    .unwrap();
                    store.past_epoch_trees.push(copy);
                }
                "over-capacity" => store.max_epochs = 0,
                _ => unreachable!(),
            }
            provider
                .0
                .storage()
                .write_message_secrets(group_id, &store)?;
            Ok(export(&provider.0, group_id))
        })
        .unwrap();
        assert!(
            super::inspect_group_retention(&invalid).is_err(),
            "invalid retained-epoch metadata cannot grant a terminal pass-over: {mode}"
        );
        assert!(
            super::migrate_group_retention_to_three(&invalid).is_err(),
            "no replacement for invalid retained-epoch metadata: {mode}"
        );
    }
}

fn config_only(state: &[u8], capacity: usize) -> Vec<u8> {
    super::with_state(state, |_, provider, group_id| {
        let (_, _, config) = super::read_retention(provider, group_id)?;
        let mut value = serde_json::to_value(config)?;
        value["max_past_epochs"] = capacity.into();
        let config: MlsGroupJoinConfig = serde_json::from_value(value)?;
        provider
            .0
            .storage()
            .write_mls_join_config(group_id, &config)?;
        Ok(export(&provider.0, group_id))
    })
    .unwrap()
}

#[test]
fn configured_capacity_cannot_impersonate_the_effective_window() {
    let (_, alice) = identity("retention-alice", false);
    let (package, bob) = identity("retention-bob", false);
    let (mut sender, welcome, _) = add(
        zero_capacity_founder(&alice, false),
        alice.clone(),
        package,
        false,
    );
    let receiver = zero_capacity_join(&welcome, &bob, false);
    let mut receiver = config_only(&receiver, 3);
    let (next, queued) =
        encrypt_message(sender, alice.clone(), b"config-only has no keys".to_vec()).unwrap();
    sender = next;
    for transition in 1..=3 {
        let metadata = super::inspect_group_retention(&receiver).unwrap();
        assert_eq!(metadata.configured_max_past_epochs, 3);
        assert_eq!(
            metadata.effective_max_past_epochs, 0,
            "configuration is not the persisted capacity"
        );
        let (package, _) = identity(&format!("config-only-{transition}"), false);
        let (next, _, commit) = add(sender, alice.clone(), package, false);
        sender = next;
        receiver = merge(receiver, bob.clone(), commit, false);
    }
    assert_eq!(
        super::inspect_group_retention(&receiver)
            .unwrap()
            .effective_max_past_epochs,
        0
    );
    assert!(
        decrypt_message(receiver.clone(), bob.clone(), queued.clone()).is_err(),
        "config-only changes never resize the effective store on Commit"
    );
    let upgraded = migrated(&receiver);
    let metadata = super::inspect_group_retention(&upgraded).unwrap();
    assert_eq!(metadata.effective_max_past_epochs, 3);
    assert!(metadata.retained_epochs.is_empty());
    assert!(
        decrypt_message(upgraded, bob, queued).is_err(),
        "migration cannot backfill already erased in-window keys"
    );
}

#[test]
fn migration_preserves_every_secret_payload_and_unrelated_entry_and_is_idempotent() {
    let (_, alice) = identity("retention-alice", false);
    let mut state: GroupState =
        serde_json::from_slice(&zero_capacity_founder(&alice, false)).unwrap();
    state
        .storage_map
        .push((b"unrelated-public-entry".to_vec(), b"untouched".to_vec()));
    let bytes = serde_json::to_vec(&state).unwrap();
    let changed = migrated(&bytes);
    let after: GroupState = serde_json::from_slice(&changed).unwrap();
    let mut altered = 0;
    for (key, old) in &state.storage_map {
        let new = &after
            .storage_map
            .iter()
            .find(|(other, _)| other == key)
            .unwrap()
            .1;
        if old != new {
            let mut old: serde_json::Value = serde_json::from_slice(old).unwrap();
            let mut new: serde_json::Value = serde_json::from_slice(new).unwrap();
            let field = if old.get("max_epochs").is_some() {
                "max_epochs"
            } else {
                "max_past_epochs"
            };
            assert_eq!(old[field], 0);
            assert_eq!(new[field], 3);
            old.as_object_mut().unwrap().remove(field);
            new.as_object_mut().unwrap().remove(field);
            assert!(
                old == new,
                "only the capacity/config field changes, including pending/current secret payloads"
            );
            altered += 1;
        }
    }
    assert_eq!(altered, 2);
    assert_eq!(state.storage_map.len(), after.storage_map.len());
    assert!(
        super::migrate_group_retention_to_three(&changed)
            .unwrap()
            .is_none(),
        "coherent migration is a no-op"
    );
    let metadata = super::inspect_group_retention(&changed).unwrap();
    assert_eq!(metadata.effective_max_past_epochs, 3);
    assert!(
        metadata.retained_epochs.is_empty(),
        "capacity is three even before any history exists"
    );
    assert_eq!(
        bytes,
        serde_json::to_vec(&state).unwrap(),
        "borrowed original state is unchanged"
    );
}

#[test]
fn larger_windows_are_preserved_and_incoherent_larger_windows_are_refused() {
    let (_, alice) = identity("retention-alice", false);
    let initial = zero_capacity_founder(&alice, false);
    let larger = super::with_state(&initial, |_, provider, group_id| {
        let (_, mut store, _) = super::read_retention(provider, group_id)?;
        store.max_epochs = 4;
        provider
            .0
            .storage()
            .write_message_secrets(group_id, &store)?;
        Ok(export(&provider.0, group_id))
    })
    .unwrap();
    assert!(
        super::migrate_group_retention_to_three(&larger).is_err(),
        "never shrink or normalize an incoherent larger store"
    );
    let coherent = config_only(&larger, 4);
    assert_eq!(
        super::inspect_group_retention(&coherent)
            .unwrap()
            .effective_max_past_epochs,
        4
    );
    assert!(super::migrate_group_retention_to_three(&coherent)
        .unwrap()
        .is_none());
}

#[test]
fn corrupt_missing_duplicate_and_unsupported_store_shapes_return_errors_without_unwinding() {
    let (_, alice) = identity("retention-alice", false);
    let initial = zero_capacity_founder(&alice, false);
    let mut cases = vec![b"invalid".to_vec()];
    let mut corrupt_context: GroupState = serde_json::from_slice(&initial).unwrap();
    let context = corrupt_context
        .storage_map
        .iter_mut()
        .find(|(key, _)| key.starts_with(b"GroupContext"))
        .expect("the real persisted context entry");
    context.1 = b"malformed context metadata".to_vec();
    cases.push(serde_json::to_vec(&corrupt_context).unwrap());
    let state: GroupState = serde_json::from_slice(&initial).unwrap();
    let mut duplicate: GroupState = serde_json::from_slice(&initial).unwrap();
    duplicate.storage_map.push(state.storage_map[0].clone());
    cases.push(serde_json::to_vec(&duplicate).unwrap());
    for replacement in [None, Some(b"invalid".to_vec()), Some(b"{}".to_vec())] {
        let mut damaged: GroupState = serde_json::from_slice(&initial).unwrap();
        let at = damaged
            .storage_map
            .iter()
            .position(|(_, bytes)| {
                serde_json::from_slice::<serde_json::Value>(bytes)
                    .is_ok_and(|v| v.get("max_epochs").is_some())
            })
            .unwrap();
        match replacement {
            Some(bytes) => damaged.storage_map[at].1 = bytes,
            None => {
                damaged.storage_map.remove(at);
            }
        }
        cases.push(serde_json::to_vec(&damaged).unwrap());
    }
    let mut unsupported: GroupState = serde_json::from_slice(&initial).unwrap();
    for (_, bytes) in &mut unsupported.storage_map {
        if let Ok(mut value) = serde_json::from_slice::<serde_json::Value>(bytes) {
            if value.get("max_epochs").is_some() {
                value["unsupported_field"] = true.into();
                *bytes = serde_json::to_vec(&value).unwrap();
            }
        }
    }
    cases.push(serde_json::to_vec(&unsupported).unwrap());
    for bytes in cases {
        let result = std::panic::catch_unwind(|| super::inspect_group_retention(&bytes));
        assert!(
            result.is_ok(),
            "inspection contains corrupt-provider panics"
        );
        assert!(result.unwrap().is_err());
        let result = std::panic::catch_unwind(|| super::migrate_group_retention_to_three(&bytes));
        assert!(result.is_ok(), "migration contains corrupt-provider panics");
        assert!(
            result.unwrap().is_err(),
            "no replacement may escape corrupt or ambiguous storage"
        );
    }
}

#[test]
fn a_retained_application_is_attributed_to_its_historical_sender_after_leaf_reuse() {
    let (_, alice) = identity("retention-alice", false);
    let (package, bob) = identity("retention-bob", false);
    let (founder, welcome, _) = add(
        zero_capacity_founder(&alice, false),
        alice.clone(),
        package,
        false,
    );
    let founder = migrated(&founder);
    let recipient = zero_capacity_join(&welcome, &bob, false);
    let (_, queued) =
        encrypt_message(recipient, bob.clone(), b"historical bob message".to_vec()).unwrap();
    let bob_identity: IdentityBundle = serde_json::from_slice(&bob).unwrap();
    let (removed, _) =
        remove_member_by_credential(founder, alice.clone(), "retention-bob".into()).unwrap();
    let (package, charlie) = identity("retention-charlie", false);
    let charlie_identity: IdentityBundle = serde_json::from_slice(&charlie).unwrap();
    let (reused, _, _) = add(removed, alice.clone(), package, false);
    let received = decrypt_message(reused, alice, queued);
    assert!(
        received.is_ok(),
        "a retained removed sender still authenticates: {:?}",
        received.as_ref().err()
    );
    let (_, body, sender) = received.unwrap();
    assert_eq!(body, b"historical bob message");
    assert_ne!(
        bob_identity.public_key_bytes,
        charlie_identity.public_key_bytes
    );
    assert_eq!(
        sender.signature_key, bob_identity.public_key_bytes,
        "historical sender cannot be replaced by the current occupant of its leaf"
    );
}

fn existing_group_window(mimi: bool) {
    let (_, alice) = identity("retention-alice", mimi);
    let (package, bob) = identity("retention-bob", mimi);
    let initial = zero_capacity_founder(&alice, mimi);
    let (mut founder, welcome, _) = add(initial, alice.clone(), package, mimi);
    let mut recipient = zero_capacity_join(&welcome, &bob, mimi);
    let before = crate::mls::inspection::inspect_group_state(&recipient).unwrap();
    assert_eq!(
        before.max_past_epochs, 0,
        "genuine zero-config Welcome recipient"
    );
    let (next, from_bob_a) = encrypt_message(
        recipient,
        bob.clone(),
        b"from bob at original epoch".to_vec(),
    )
    .unwrap();
    let (next, from_bob_b) =
        encrypt_message(next, bob.clone(), b"evicted bob message".to_vec()).unwrap();
    recipient = migrated(&next);
    let (next, from_alice_a) = encrypt_message(
        founder,
        alice.clone(),
        b"from alice at original epoch".to_vec(),
    )
    .unwrap();
    let (next, from_alice_b) =
        encrypt_message(next, alice.clone(), b"evicted alice message".to_vec()).unwrap();
    founder = migrated(&next);
    let mut queued = Vec::new();
    for transition in 1..=4 {
        let (package, _) = identity(&format!("retention-extra-{transition}"), mimi);
        let (next, _, commit) = add(founder, alice.clone(), package, mimi);
        founder = next;
        recipient = merge(recipient, bob.clone(), commit, mimi);
        let epoch = crate::mls::inspection::inspect_group_state(&recipient)
            .unwrap()
            .epoch;
        assert_eq!(epoch, before.epoch + transition);
        if transition == 3 {
            let received = decrypt_message(recipient.clone(), bob.clone(), from_alice_a.clone());
            assert!(
                received.is_ok(),
                "distance-three application must authenticate after explicit migration: {:?}",
                received.as_ref().err()
            );
            assert_eq!(received.unwrap().1, b"from alice at original epoch");
            assert_eq!(
                decrypt_message(founder.clone(), alice.clone(), from_bob_a.clone())
                    .unwrap()
                    .1,
                b"from bob at original epoch"
            );
        }
        if transition < 4 {
            let body = format!("queued at transition {transition}").into_bytes();
            let (next, wire) = encrypt_message(founder, alice.clone(), body.clone()).unwrap();
            founder = next;
            queued.push((wire, body));
        }
    }
    assert!(
        decrypt_message(recipient.clone(), bob.clone(), from_alice_b).is_err(),
        "distance-four application must be evicted"
    );
    assert!(
        decrypt_message(founder, alice, from_bob_b).is_err(),
        "founder also evicts distance-four secrets"
    );
    for (wire, body) in queued {
        assert_eq!(
            decrypt_message(recipient.clone(), bob.clone(), wire)
                .unwrap()
                .1,
            body,
            "distances one through three remain readable after reopen"
        );
    }
}

#[test]
fn an_existing_zero_capacity_group_decrypts_at_distance_three_after_migration() {
    existing_group_window(false);
}

#[test]
fn an_existing_mimi_founder_and_welcome_recipient_retain_three_then_evict_four() {
    existing_group_window(true);
}

#[test]
fn all_creation_and_join_builders_install_the_effective_three_epoch_policy() {
    let (_, alice) = identity("policy-alice", false);
    let (package, bob) = identity("policy-bob", false);
    let initial = create_group("policy-native".into(), alice.clone()).unwrap();
    let (founder, welcome, _) = add_member(initial.clone(), alice, package).unwrap();
    let (recipient, _) = process_welcome(welcome, bob).unwrap();
    let (_, alice) = identity("policy-mimi-alice", true);
    let (package, bob) = identity("policy-mimi-bob", true);
    let plain = crate::mimi::mimi_create_group("policy-mimi-plain".into(), alice.clone()).unwrap();
    let (_, hub) = identity("policy-hub", true);
    let hub: IdentityBundle = serde_json::from_slice(&hub).unwrap();
    let external = crate::mimi::mimi_create_group_with_external_senders(
        "policy-mimi-external".into(),
        alice.clone(),
        hub.public_key_bytes.clone(),
        "policy-hub".into(),
    )
    .unwrap();
    let (external_founder, welcome, _) =
        crate::mimi::mimi_add_member_commit(external.clone(), alice, package).unwrap();
    let prepared = crate::mimi::prepare_welcome_retirement(
        welcome,
        bob,
        hub.public_key_bytes.clone(),
        "policy-hub".into(),
    )
    .unwrap();
    let (external_recipient, _) = crate::mimi::complete_welcome(prepared).unwrap();
    for state in [
        initial,
        founder,
        recipient,
        plain,
        external,
        external_founder,
        external_recipient,
    ] {
        let metadata = super::inspect_group_retention(&state).unwrap();
        assert_eq!(metadata.configured_max_past_epochs, 3);
        assert_eq!(
            metadata.effective_max_past_epochs, 3,
            "every native/MIMI founder and Welcome path retains three"
        );
    }
}

#[test]
fn a_production_creation_or_join_builder_cannot_omit_the_shared_retention_policy() {
    fn check(directory: &std::path::Path, builders: &mut usize) {
        for entry in std::fs::read_dir(directory).unwrap() {
            let path = entry.unwrap().path();
            let name = path.file_stem().unwrap().to_string_lossy();
            if name.contains("tests") {
                continue;
            }
            if path.is_dir() {
                check(&path, builders);
                continue;
            }
            if path.extension().is_none_or(|extension| extension != "rs") {
                continue;
            }
            let source = std::fs::read_to_string(&path).unwrap();
            let production = source.as_str();
            for kind in ["MlsGroupCreateConfig", "MlsGroupJoinConfig"] {
                assert!(
                    !production.contains(&format!("{kind}::default()")),
                    "group defaults bypass explicit retention: {}",
                    path.display()
                );
                let prefix = format!("{kind}::builder()");
                for suffix in production.split(&prefix).skip(1) {
                    *builders += 1;
                    let configuration = suffix.split(".build()").next().unwrap();
                    assert!(
                        configuration.contains(
                            ".max_past_epochs(crate::mls::retention::PAST_EPOCH_RETENTION)"
                        ),
                        "builder must explicitly install the shared receive window: {}",
                        path.display()
                    );
                }
            }
        }
    }
    let mut builders = 0;
    check(
        &std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src"),
        &mut builders,
    );
    assert_eq!(
        builders, 5,
        "new production builders require behavioral retention coverage"
    );
}

#[test]
fn a_pending_commit_keeps_its_epoch_and_artifact_until_its_owner_merges_it() {
    use tls_codec::Serialize as _;
    let (_, alice) = identity("retention-alice", false);
    let (package, bob) = identity("retention-bob", false);
    let (founder, welcome, _) = add(
        zero_capacity_founder(&alice, false),
        alice.clone(),
        package,
        false,
    );
    let receiver = zero_capacity_join(&welcome, &bob, false);
    let (receiver, queued) =
        encrypt_message(receiver, bob.clone(), b"before pending Commit".to_vec()).unwrap();
    let (_, evicted) =
        encrypt_message(receiver, bob, b"evicted after pending Commit".to_vec()).unwrap();
    let (package, _) = identity("pending-retention-extra", false);
    let (pending, original_commit) = super::with_state(&founder, |_, provider, group_id| {
        let mut group = MlsGroup::load(provider.0.storage(), group_id)?.unwrap();
        let identity: IdentityBundle = serde_json::from_slice(&alice)?;
        let signer = MlsSigner {
            key: Zeroizing::new(identity.private_key.clone()),
            scheme: identity.signature_scheme,
        };
        let package = KeyPackageIn::tls_deserialize_exact(&package)?
            .validate(provider.0.crypto(), ProtocolVersion::Mls10)?;
        let (commit, _, _) = group.add_members(&provider.0, &signer, &[package])?;
        assert!(group.pending_commit().is_some());
        Ok((
            export(&provider.0, group_id),
            commit.tls_serialize_detached()?,
        ))
    })
    .unwrap();
    let prior = super::inspect_group_retention(&pending).unwrap();
    let upgraded = migrated(&pending);
    assert_eq!(
        super::inspect_group_retention(&upgraded).unwrap().epoch,
        prior.epoch,
        "migration never publishes a pending MLS epoch"
    );
    let pending_state_entry = |bytes: &[u8]| {
        let state: GroupState = serde_json::from_slice(bytes).unwrap();
        state
            .storage_map
            .iter()
            .find(|(key, _)| key.starts_with(b"GroupState"))
            .unwrap()
            .1
            .clone()
    };
    assert!(
        pending_state_entry(&pending) == pending_state_entry(&upgraded),
        "the serialized pending Commit stays byte-identical"
    );
    assert!(!original_commit.is_empty());
    let mut current = super::with_state(&upgraded, |_, provider, group_id| {
        let mut group = MlsGroup::load(provider.0.storage(), group_id)?.unwrap();
        assert!(
            group.pending_commit().is_some(),
            "retention inspection/migration leaves pending ownership intact"
        );
        group.merge_pending_commit(&provider.0)?;
        Ok(export(&provider.0, group_id))
    })
    .unwrap();
    for transition in 0..2 {
        let (package, _) = identity(&format!("pending-retention-later-{transition}"), false);
        current = add(current, alice.clone(), package, false).0;
    }
    assert_eq!(
        super::inspect_group_retention(&current).unwrap().epoch,
        prior.epoch + 3
    );
    assert_eq!(
        decrypt_message(current.clone(), alice.clone(), queued)
            .unwrap()
            .1,
        b"before pending Commit",
        "the owner merge uses the migrated effective store for the prior epoch"
    );
    let (package, _) = identity("pending-retention-final", false);
    current = add(current, alice.clone(), package, false).0;
    assert!(
        decrypt_message(current, alice, evicted).is_err(),
        "the same pending-origin epoch evicts at distance four"
    );
}

#[test]
fn an_unknown_join_configuration_field_is_refused_instead_of_silently_dropped() {
    let (_, alice) = identity("retention-alice", false);
    let initial = zero_capacity_founder(&alice, false);
    let mut state: GroupState = serde_json::from_slice(&initial).unwrap();
    let mut changed = 0;
    for (_, bytes) in &mut state.storage_map {
        if let Ok(mut configuration) = serde_json::from_slice::<serde_json::Value>(bytes) {
            if configuration.get("max_past_epochs").is_some() {
                configuration["future_configuration_option"] = true.into();
                *bytes = serde_json::to_vec(&configuration).unwrap();
                changed += 1;
            }
        }
    }
    assert_eq!(changed, 1);
    let unsupported = serde_json::to_vec(&state).unwrap();
    assert!(
        super::inspect_group_retention(&unsupported).is_err(),
        "configuration must round-trip through the locked typed schema without loss"
    );
    assert!(
        super::migrate_group_retention_to_three(&unsupported).is_err(),
        "never return a replacement that drops an unrecognized configuration field"
    );
    assert_eq!(
        unsupported,
        serde_json::to_vec(&state).unwrap(),
        "a refused migration leaves borrowed state unchanged"
    );
}

#[test]
fn current_secrets_from_another_tree_with_the_same_group_id_and_epoch_are_refused() {
    let (_, alice) = identity("retention-alice", false);
    let (_, bob) = identity("retention-unrelated-founder", false);
    let initial = zero_capacity_founder(&alice, false);
    let other = zero_capacity_founder(&bob, false);
    let original_context = crate::mls::inspection::inspect_group_state(&initial).unwrap();
    let other_context = crate::mls::inspection::inspect_group_state(&other).unwrap();
    assert_eq!(original_context.group_id, other_context.group_id);
    assert_eq!(original_context.epoch, other_context.epoch);
    let store = super::with_state(&other, |_, provider, group_id| {
        Ok(super::read_retention(provider, group_id)?.1)
    })
    .unwrap();
    let mixed = super::with_state(&initial, |_, provider, group_id| {
        provider
            .0
            .storage()
            .write_message_secrets(group_id, &store)?;
        Ok(export(&provider.0, group_id))
    })
    .unwrap();
    assert!(super::inspect_group_retention(&mixed).is_err(), "current secret context must match the complete actual group context, including its tree hash");
    assert!(
        super::migrate_group_retention_to_three(&mixed).is_err(),
        "a same-id/same-epoch transplant is not a valid migration source"
    );
}
