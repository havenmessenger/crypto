//! Known-answer tests.
//!
//! * `rfc9420_*`: the labelled primitives against the published RFC 9420 crypto-basics vectors.
//! * `stored_message_*`: a sealed message and the two members' stored group state, checked into
//!   the repository. A later change must still open it (`stored_message_opens`) and, because the
//!   HPKE ephemeral randomness, the exporter secrets and Ed25519 are all fixed by the stored
//!   state and seed, must still produce these exact bytes (`stored_message_is_reproduced_byte_for_byte`).
//!   The vector file is regenerated only by the ignored `regenerate_stored_message` test.

use openmls::prelude::*;
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::OpenMlsProvider;
use serde_json::Value;
use zeroize::Zeroizing;

use super::support::*;
use crate::mls::targeted::{hpke, labels, open, seal};
use crate::mls::MlsSigner;
use crate::suite_policy::targeted_message_suite;

const RFC_VECTORS: &str = include_str!("../testdata/rfc9420_crypto_basics.json");
const STORED_MESSAGE: &str = include_str!("../testdata/stored_message_v1.json");
const STORED_MESSAGE_PATH: &str = "src/mls/targeted/testdata/stored_message_v1.json";

fn unhex(value: &Value) -> Vec<u8> {
    hex::decode(value.as_str().expect("hex string")).expect("valid hex")
}

fn suite_of(id: u64) -> Ciphersuite {
    Ciphersuite::try_from(u16::try_from(id).expect("suite id")).expect("known suite")
}

#[test]
fn rfc9420_expand_with_label_vectors() {
    let vectors: Value = serde_json::from_str(RFC_VECTORS).expect("vector file");
    let provider = OpenMlsRustCrypto::default();
    let mut checked = 0;
    for vector in vectors["vectors"].as_array().expect("vectors") {
        let suite = suite_of(vector["cipher_suite"].as_u64().expect("suite"));
        let case = &vector["expand_with_label"];
        let out = labels::expand_with_label(
            provider.crypto(),
            suite.hash_algorithm(),
            &unhex(&case["secret"]),
            case["label"].as_str().expect("label"),
            &unhex(&case["context"]),
            usize::try_from(case["length"].as_u64().expect("length")).expect("length"),
        )
        .expect("expand");
        assert_eq!(
            out.as_slice(),
            unhex(&case["out"]).as_slice(),
            "suite {suite:?}"
        );
        checked += 1;
    }
    assert_eq!(checked, 3);
}

#[test]
fn rfc9420_sign_with_label_vectors() {
    let vectors: Value = serde_json::from_str(RFC_VECTORS).expect("vector file");
    let provider = OpenMlsRustCrypto::default();
    let mut checked = 0;
    for vector in vectors["vectors"].as_array().expect("vectors") {
        let suite = suite_of(vector["cipher_suite"].as_u64().expect("suite"));
        let case = &vector["sign_with_label"];
        let label = case["label"].as_str().expect("label");
        let content = unhex(&case["content"]);
        let public = unhex(&case["pub"]);
        let signature = unhex(&case["signature"]);
        let scheme = suite.signature_algorithm();

        assert!(
            labels::verify_with_label(
                provider.crypto(),
                scheme,
                &public,
                label,
                &content,
                &signature
            ),
            "the published signature verifies, suite {suite:?}"
        );
        let mut altered = content.clone();
        altered[0] ^= 1;
        assert!(
            !labels::verify_with_label(
                provider.crypto(),
                scheme,
                &public,
                label,
                &altered,
                &signature
            ),
            "a changed content does not"
        );
        assert!(
            !labels::verify_with_label(
                provider.crypto(),
                scheme,
                &public,
                "Other",
                &content,
                &signature
            ),
            "a changed label does not"
        );

        let signer = MlsSigner {
            key: Zeroizing::new(unhex(&case["priv"])),
            scheme,
        };
        let produced = labels::sign_with_label(&signer, label, &content).expect("sign");
        assert!(
            labels::verify_with_label(
                provider.crypto(),
                scheme,
                &public,
                label,
                &content,
                &produced
            ),
            "our own signature verifies under the published public key"
        );
        if scheme == openmls_traits::types::SignatureScheme::ED25519 {
            assert_eq!(
                produced, signature,
                "Ed25519 is deterministic: byte-equal to the vector"
            );
        }
        checked += 1;
    }
    assert_eq!(checked, 3);
}

fn storage_snapshot(provider: &OpenMlsRustCrypto) -> Vec<(String, String)> {
    let values = provider.storage().values.read().expect("storage");
    let mut pairs: Vec<(String, String)> = values
        .iter()
        .map(|(k, v)| (hex::encode(k), hex::encode(v)))
        .collect();
    pairs.sort();
    pairs
}

fn load_group(storage: &Value, group_id: &[u8]) -> (OpenMlsRustCrypto, MlsGroup) {
    let provider = OpenMlsRustCrypto::default();
    {
        let mut values = provider.storage().values.write().expect("storage");
        *values = storage
            .as_array()
            .expect("storage pairs")
            .iter()
            .map(|pair| (unhex(&pair[0]), unhex(&pair[1])))
            .collect();
    }
    let group = MlsGroup::load(provider.storage(), &GroupId::from_slice(group_id))
        .expect("storage read")
        .expect("group present");
    (provider, group)
}

fn vector() -> Value {
    serde_json::from_str(STORED_MESSAGE).expect("stored message vector")
}

#[test]
fn stored_message_opens() {
    let vector = vector();
    let group_id = unhex(&vector["group_id"]);
    let (provider, group) = load_group(&vector["recipient"]["storage"], &group_id);
    assert_eq!(group.own_leaf_index().u32(), 1);
    let opened =
        open(&provider, &group, &unhex(&vector["envelope"])).expect("the stored message opens");
    assert_eq!(opened.sender_leaf_index, 0);
    assert_eq!(
        opened.authenticated_data,
        unhex(&vector["authenticated_data"])
    );
    assert_eq!(
        opened.application_data.as_slice(),
        unhex(&vector["application_data"]).as_slice()
    );
}

#[test]
fn stored_message_is_reproduced_byte_for_byte() {
    let vector = vector();
    let group_id = unhex(&vector["group_id"]);
    let (provider, group) = load_group(&vector["sender"]["storage"], &group_id);
    let suite = targeted_message_suite(group.ciphersuite()).expect("suite");
    let signer = MlsSigner {
        key: Zeroizing::new(unhex(&vector["sender"]["signature_private_key"])),
        scheme: suite.signature,
    };
    hpke::EPHEMERAL_SEED.with(|seed| *seed.borrow_mut() = Some(unhex(&vector["ephemeral_seed"])));
    let sealed = seal(
        &provider,
        &group,
        &signer,
        LeafNodeIndex::new(1),
        &unhex(&vector["authenticated_data"]),
        &unhex(&vector["application_data"]),
        usize::try_from(vector["padding_len"].as_u64().expect("padding")).expect("padding"),
    )
    .expect("seal");
    assert_eq!(
        hex::encode(sealed),
        vector["envelope"].as_str().expect("envelope")
    );
}

#[test]
fn the_stored_message_is_a_draft_01_envelope_for_a_three_member_group() {
    let vector = vector();
    assert_eq!(vector["draft_version"].as_u64(), Some(1));
    let envelope = unhex(&vector["envelope"]);
    assert_eq!(
        &envelope[..2],
        &[0, 1],
        "the envelope opens with draft_version 1"
    );
}

/// Regenerates the stored vector: `cargo test --lib regenerate_stored_message -- --ignored`.
/// The file is public test data: a throwaway group with throwaway keys.
#[test]
#[ignore = "rewrites the checked-in vector"]
fn regenerate_stored_message() {
    let (a, b, _c) = three();
    let authenticated_data = b"targeted-message-vector-ad".to_vec();
    let application_data = b"operators-only preview: rm -rf ./build".to_vec();
    let padding_len = 5usize;
    let seed = [0x42u8; 32];
    hpke::EPHEMERAL_SEED.with(|cell| *cell.borrow_mut() = Some(seed.to_vec()));
    let sealed = seal(
        &a.provider,
        a.group(),
        &a.signer,
        b.leaf(),
        &authenticated_data,
        &application_data,
        padding_len,
    )
    .expect("seal");
    let vector = serde_json::json!({
        "description": "A targeted message from leaf 0 to leaf 1 of a three-member group, with both members' stored group state. draft_version 1 is draft-ietf-mls-targeted-messages-01.",
        "draft_version": 1,
        "group_id": hex::encode(a.group().group_id().as_slice()),
        "epoch": a.group().epoch().as_u64(),
        "authenticated_data": hex::encode(&authenticated_data),
        "application_data": hex::encode(&application_data),
        "padding_len": padding_len,
        "ephemeral_seed": hex::encode(seed),
        "sender": {
            "leaf": 0,
            "signature_private_key": hex::encode(a.signer.key.as_slice()),
            "storage": storage_snapshot(&a.provider),
        },
        "recipient": {
            "leaf": 1,
            "storage": storage_snapshot(&b.provider),
        },
        "envelope": hex::encode(sealed),
    });
    std::fs::write(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(STORED_MESSAGE_PATH),
        serde_json::to_string_pretty(&vector).expect("json") + "\n",
    )
    .expect("write vector");
}
