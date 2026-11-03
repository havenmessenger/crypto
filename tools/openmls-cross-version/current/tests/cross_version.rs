//! crypto-core across an openmls release change.
//!
//! `Release::Previous` is crypto-core on openmls 0.8.1, run as the `../previous` driver; `Release::Current`
//! is this checkout, called in process. Both answer the same operations with the same JSON, so each test
//! says which release performs each step and hands bytes between them exactly as a device would: state
//! from storage, messages from the wire.

use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::OnceLock;

use crypto_core::identity::generate_identity;
use crypto_core::mimi::{
    complete_welcome, mimi_add_member_commit, mimi_add_member_commit_pending, mimi_create_group,
    mimi_generate_identity, mimi_send_handshake_privately, prepare_welcome_retirement,
};
use crypto_core::mls::groups::{
    add_member, add_member_pending, create_group, decrypt_message, encrypt_message,
    list_members_with_indices, mls_process_commit, process_welcome, remove_member_by_leaf_index,
};
use crypto_core::mls::inspection::inspect_group_state;
use crypto_core::mls::{CommitAcceptance, PendingCommit};
use serde_json::{json, Value};

/// Key packages carry a lifetime, so identities are made at the current time.
fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("a clock after 1970")
        .as_secs()
        .try_into()
        .expect("a clock before 2262")
}

#[derive(Clone, Copy, Debug)]
enum Release {
    Previous,
    Current,
}
use Release::{Current, Previous};

/// The previous release's driver, built once from its own lockfile.
fn previous_driver() -> &'static PathBuf {
    static DRIVER: OnceLock<PathBuf> = OnceLock::new();
    DRIVER.get_or_init(|| {
        let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../previous/Cargo.toml");
        let target = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("previous");
        let status = Command::new(env!("CARGO"))
            .args(["build", "--locked", "--quiet", "--manifest-path"])
            .arg(&manifest)
            .arg("--target-dir")
            .arg(&target)
            .status()
            .expect("cargo runs");
        assert!(status.success(), "the previous release's driver builds");
        target.join("debug").join("previous-driver")
    })
}

fn bytes(request: &Value, field: &str) -> Vec<u8> {
    hex::decode(request[field].as_str().expect(field)).expect(field)
}

fn text(request: &Value, field: &str) -> String {
    request[field].as_str().expect(field).to_owned()
}

fn answer(parts: &[&[u8]]) -> Value {
    json!({ "ok": parts.iter().map(hex::encode).collect::<Vec<_>>() })
}

/// The same operations as `../previous/src/main.rs`, on this checkout.
fn current(request: &Value) -> anyhow::Result<Value> {
    Ok(match request["op"].as_str().expect("op") {
        "generate_identity" => {
            let (_, key_package, bundle) = generate_identity(text(request, "user"), now())?;
            answer(&[&key_package, &bundle])
        }
        "mimi_generate_identity" => {
            let (_, key_package, bundle) = mimi_generate_identity(text(request, "user"), now())?;
            answer(&[&key_package, &bundle])
        }
        "create_group" => answer(&[&create_group(
            text(request, "group"),
            bytes(request, "bundle"),
        )?]),
        "mimi_create_group" => answer(&[&mimi_create_group(
            text(request, "group"),
            bytes(request, "bundle"),
        )?]),
        "add_member" => {
            let (state, welcome, commit) = add_member(
                bytes(request, "state"),
                bytes(request, "bundle"),
                bytes(request, "key_package"),
            )?;
            answer(&[&state, &welcome, &commit])
        }
        "mimi_add_member_commit" => {
            let (state, welcome, commit) = mimi_add_member_commit(
                bytes(request, "state"),
                bytes(request, "bundle"),
                bytes(request, "key_package"),
            )?;
            answer(&[&state, &welcome, &commit])
        }
        "add_member_pending" | "mimi_add_member_commit_pending" => {
            let stage = if request["op"] == "add_member_pending" {
                add_member_pending
            } else {
                mimi_add_member_commit_pending
            };
            let mut pending = stage(
                bytes(request, "state"),
                bytes(request, "bundle"),
                bytes(request, "key_package"),
            )?;
            pending.bind_submission(&bytes(request, "submission"))?;
            let welcome = pending.welcome().unwrap_or_default().to_vec();
            answer(&[&pending.to_bytes()?, pending.commit(), &welcome])
        }
        "mimi_send_handshake_privately" => answer(&[&mimi_send_handshake_privately(
            bytes(request, "state"),
            bytes(request, "bundle"),
        )?]),
        "process_welcome" => {
            let (state, bundle) =
                process_welcome(bytes(request, "welcome"), bytes(request, "bundle"))?;
            answer(&[&state, &bundle])
        }
        "mimi_join" => {
            let prepared = prepare_welcome_retirement(
                bytes(request, "welcome"),
                bytes(request, "bundle"),
                Vec::new(),
                String::new(),
            )
            .map_err(|error| anyhow::anyhow!("{error:?}"))?;
            let (state, bundle) =
                complete_welcome(prepared).map_err(|error| anyhow::anyhow!("{error:?}"))?;
            answer(&[&state, &bundle])
        }
        "encrypt" => {
            let (state, ciphertext) = encrypt_message(
                bytes(request, "state"),
                bytes(request, "bundle"),
                bytes(request, "plaintext"),
            )?;
            answer(&[&state, &ciphertext])
        }
        "decrypt" => {
            let (state, plaintext, _) = decrypt_message(
                bytes(request, "state"),
                bytes(request, "bundle"),
                bytes(request, "ciphertext"),
            )?;
            answer(&[&state, &plaintext])
        }
        "process_commit" => {
            let (state, _) = mls_process_commit(
                bytes(request, "state"),
                bytes(request, "bundle"),
                bytes(request, "commit"),
            )?;
            answer(&[&state])
        }
        "remove_leaf" => {
            let (state, commit) = remove_member_by_leaf_index(
                bytes(request, "state"),
                bytes(request, "bundle"),
                u32::try_from(request["leaf"].as_u64().expect("leaf"))?,
                text(request, "signature_key"),
            )?;
            answer(&[&state, &commit])
        }
        "members" => {
            let members = list_members_with_indices(bytes(request, "state"))?;
            json!({ "members": members.iter().map(|member| json!({
                "leaf": member.leaf_index,
                "identity": hex::encode(&member.credential_identity),
                "signature_key": member.signature_key,
            })).collect::<Vec<_>>() })
        }
        "inspect" => {
            let metadata = inspect_group_state(&bytes(request, "state"))?;
            json!({ "epoch": metadata.epoch, "max_past_epochs": metadata.max_past_epochs })
        }
        "confirm" => {
            let pending = PendingCommit::from_bytes(&bytes(request, "pending"))?;
            let acceptance = CommitAcceptance::new(
                pending.group_id(),
                pending.predecessor_epoch(),
                pending.commit(),
                &bytes(request, "submission"),
            );
            let state = pending
                .confirm(&bytes(request, "canonical"), &acceptance)
                .map_err(|refused| anyhow::anyhow!("{refused:?}"))?;
            answer(&[&state.into_bytes()])
        }
        "abandon" => {
            let pending = PendingCommit::from_bytes(&bytes(request, "pending"))?;
            answer(&[&pending.abandon()?.into_bytes()])
        }
        other => anyhow::bail!("unknown operation {other}"),
    })
}

/// Run one operation on `release`. `Err` carries the release's own refusal text.
fn call(release: Release, request: Value) -> Result<Value, String> {
    let answer = match release {
        Current => current(&request).unwrap_or_else(|error| json!({ "err": format!("{error:#}") })),
        Previous => {
            let mut child = Command::new(previous_driver())
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .spawn()
                .expect("the driver starts");
            child
                .stdin
                .take()
                .expect("stdin")
                .write_all(request.to_string().as_bytes())
                .expect("the request is written");
            let output = child.wait_with_output().expect("the driver finishes");
            assert!(output.status.success(), "the driver exits cleanly");
            serde_json::from_slice(&output.stdout).expect("a JSON answer")
        }
    };
    match answer.get("err") {
        Some(error) => Err(error.as_str().unwrap_or_default().to_owned()),
        None => Ok(answer),
    }
}

fn parts(release: Release, request: Value) -> Result<Vec<Vec<u8>>, String> {
    let answer = call(release, request)?;
    Ok(answer["ok"]
        .as_array()
        .expect("byte strings")
        .iter()
        .map(|part| hex::decode(part.as_str().expect("hex")).expect("hex"))
        .collect())
}

fn ok(release: Release, request: Value) -> Vec<Vec<u8>> {
    let op = request["op"].clone();
    parts(release, request).unwrap_or_else(|error| panic!("{release:?} {op}: {error}"))
}

/// A member: their bundle and, once in a group, their state.
struct Member {
    bundle: Vec<u8>,
    state: Vec<u8>,
}

fn identity(release: Release, user: &str, mimi: bool) -> (Vec<u8>, Member) {
    let op = if mimi {
        "mimi_generate_identity"
    } else {
        "generate_identity"
    };
    let mut got = ok(release, json!({ "op": op, "user": user }));
    let bundle = got.pop().unwrap();
    let key_package = got.pop().unwrap();
    (
        key_package,
        Member {
            bundle,
            state: Vec::new(),
        },
    )
}

fn create(release: Release, member: &mut Member, group: &str, mimi: bool) {
    let op = if mimi {
        "mimi_create_group"
    } else {
        "create_group"
    };
    member.state = ok(
        release,
        json!({ "op": op, "group": group, "bundle": hex::encode(&member.bundle) }),
    )
    .remove(0);
}

/// `member` adds the owner of `key_package`; returns (welcome, commit).
fn add(
    release: Release,
    member: &mut Member,
    key_package: &[u8],
    mimi: bool,
) -> (Vec<u8>, Vec<u8>) {
    let op = if mimi {
        "mimi_add_member_commit"
    } else {
        "add_member"
    };
    let mut got = ok(
        release,
        json!({ "op": op, "state": hex::encode(&member.state), "bundle": hex::encode(&member.bundle),
                "key_package": hex::encode(key_package) }),
    );
    let commit = got.pop().unwrap();
    let welcome = got.pop().unwrap();
    member.state = got.pop().unwrap();
    (welcome, commit)
}

fn join(release: Release, member: &mut Member, welcome: &[u8], mimi: bool) {
    let op = if mimi { "mimi_join" } else { "process_welcome" };
    let mut got = ok(
        release,
        json!({ "op": op, "welcome": hex::encode(welcome), "bundle": hex::encode(&member.bundle) }),
    );
    member.bundle = got.pop().unwrap();
    member.state = got.pop().unwrap();
}

fn send(release: Release, member: &mut Member, message: &str) -> Vec<u8> {
    let mut got = ok(
        release,
        json!({ "op": "encrypt", "state": hex::encode(&member.state), "bundle": hex::encode(&member.bundle),
                "plaintext": hex::encode(message) }),
    );
    let ciphertext = got.pop().unwrap();
    member.state = got.pop().unwrap();
    ciphertext
}

fn try_read(release: Release, member: &mut Member, ciphertext: &[u8]) -> Result<String, String> {
    let mut got = parts(
        release,
        json!({ "op": "decrypt", "state": hex::encode(&member.state), "bundle": hex::encode(&member.bundle),
                "ciphertext": hex::encode(ciphertext) }),
    )?;
    let plaintext = got.pop().unwrap();
    member.state = got.pop().unwrap();
    Ok(String::from_utf8(plaintext).expect("text"))
}

fn read(release: Release, member: &mut Member, ciphertext: &[u8]) -> String {
    try_read(release, member, ciphertext)
        .unwrap_or_else(|error| panic!("{release:?} decrypt: {error}"))
}

fn apply(release: Release, member: &mut Member, commit: &[u8]) {
    member.state = ok(
        release,
        json!({ "op": "process_commit", "state": hex::encode(&member.state), "bundle": hex::encode(&member.bundle),
                "commit": hex::encode(commit) }),
    )
    .remove(0);
}

/// (leaf, credential identity, signature key) of each member.
fn members(release: Release, state: &[u8]) -> Vec<(u64, Vec<u8>, String)> {
    let answer = call(
        release,
        json!({ "op": "members", "state": hex::encode(state) }),
    )
    .unwrap_or_else(|error| panic!("{release:?} members: {error}"));
    answer["members"]
        .as_array()
        .expect("members")
        .iter()
        .map(|member| {
            (
                member["leaf"].as_u64().unwrap(),
                hex::decode(member["identity"].as_str().unwrap()).unwrap(),
                member["signature_key"].as_str().unwrap().to_owned(),
            )
        })
        .collect()
}

/// `member` removes whoever's credential identity is `identity`; returns the commit.
fn remove(release: Release, member: &mut Member, identity: &str) -> Vec<u8> {
    let (leaf, _, signature_key) = members(release, &member.state)
        .into_iter()
        .find(|(_, credential, _)| credential.as_slice() == identity.as_bytes())
        .unwrap_or_else(|| panic!("{identity} is a member"));
    let mut got = ok(
        release,
        json!({ "op": "remove_leaf", "state": hex::encode(&member.state), "bundle": hex::encode(&member.bundle),
                "leaf": leaf, "signature_key": signature_key }),
    );
    let commit = got.pop().unwrap();
    member.state = got.pop().unwrap();
    commit
}

fn identities(release: Release, state: &[u8]) -> Vec<String> {
    let mut names: Vec<String> = members(release, state)
        .into_iter()
        .map(|(_, identity, _)| String::from_utf8(identity).expect("text"))
        .collect();
    names.sort();
    names
}

fn inspect(release: Release, state: &[u8]) -> Result<Value, String> {
    call(
        release,
        json!({ "op": "inspect", "state": hex::encode(state) }),
    )
}

/// A group, an identity with an unused key package, and a message in flight, all written by the
/// previous release, continue under this one: it reads the message, sends, adds the waiting member
/// from their stored bundle, and removes one.
#[test]
fn state_the_previous_release_wrote_continues_under_this_one() {
    let (_, mut alice) = identity(Previous, "alice", false);
    let (bob_key_package, mut bob) = identity(Previous, "bob", false);
    let (carol_key_package, mut carol) = identity(Previous, "carol", false);
    create(Previous, &mut alice, "state-continues", false);
    let (welcome, _) = add(Previous, &mut alice, &bob_key_package, false);
    join(Previous, &mut bob, &welcome, false);
    let first = send(Previous, &mut alice, "first");
    assert_eq!(read(Previous, &mut bob, &first), "first");
    let in_flight = send(Previous, &mut alice, "in flight");

    assert_eq!(
        inspect(Current, &alice.state),
        inspect(Previous, &alice.state),
        "both releases read the same group metadata"
    );

    assert_eq!(read(Current, &mut bob, &in_flight), "in flight");
    let reply = send(Current, &mut bob, "reply");
    assert_eq!(read(Current, &mut alice, &reply), "reply");

    let (welcome, commit) = add(Current, &mut alice, &carol_key_package, false);
    join(Current, &mut carol, &welcome, false);
    apply(Current, &mut bob, &commit);
    let everyone = send(Current, &mut alice, "everyone");
    assert_eq!(read(Current, &mut bob, &everyone), "everyone");
    assert_eq!(read(Current, &mut carol, &everyone), "everyone");

    let commit = remove(Current, &mut alice, "bob");
    apply(Current, &mut carol, &commit);
    assert_eq!(identities(Current, &carol.state), ["alice", "carol"]);
    let after = send(Current, &mut carol, "after");
    assert_eq!(read(Current, &mut alice, &after), "after");
}

/// Members on the two releases share one group: Welcome, application messages and commits in both
/// directions, and each release removing a member on the other.
#[test]
fn members_on_both_releases_share_one_group() {
    let (_, mut alice) = identity(Previous, "alice", false);
    let (bob_key_package, mut bob) = identity(Current, "bob", false);
    let (carol_key_package, mut carol) = identity(Previous, "carol", false);
    create(Previous, &mut alice, "mixed", false);

    let (welcome, _) = add(Previous, &mut alice, &bob_key_package, false);
    join(Current, &mut bob, &welcome, false);
    let hello = send(Previous, &mut alice, "from previous");
    assert_eq!(read(Current, &mut bob, &hello), "from previous");
    let hello = send(Current, &mut bob, "from current");
    assert_eq!(read(Previous, &mut alice, &hello), "from current");

    let (welcome, commit) = add(Current, &mut bob, &carol_key_package, false);
    apply(Previous, &mut alice, &commit);
    join(Previous, &mut carol, &welcome, false);
    let three = send(Previous, &mut carol, "three of us");
    assert_eq!(read(Previous, &mut alice, &three), "three of us");
    assert_eq!(read(Current, &mut bob, &three), "three of us");

    let commit = remove(Current, &mut bob, "carol");
    apply(Previous, &mut alice, &commit);
    assert_eq!(identities(Previous, &alice.state), ["alice", "bob"]);
    let two = send(Current, &mut bob, "two again");
    assert_eq!(read(Previous, &mut alice, &two), "two again");

    let commit = remove(Previous, &mut alice, "bob");
    assert_eq!(identities(Previous, &alice.state), ["alice"]);
    let removed = try_read(Current, &mut bob, &commit);
    assert!(
        removed.is_err(),
        "a commit is not an application message: {removed:?}"
    );
}

/// The same on the MIMI lane, whose groups and identities carry the participant-list capability: a
/// group created on each release, with the other release's members added, messaging and committing.
/// Only the creator adds, because on either release a member who joined by Welcome sends Welcomes
/// without the ratchet tree.
#[test]
fn members_on_both_releases_share_one_mimi_group() {
    for (creator, other) in [(Current, Previous), (Previous, Current)] {
        let (_, mut alice) = identity(creator, "alice", true);
        let (bob_key_package, mut bob) = identity(other, "bob", true);
        let (carol_key_package, mut carol) = identity(other, "carol", true);
        create(creator, &mut alice, "mixed-mimi", true);

        let (welcome, _) = add(creator, &mut alice, &bob_key_package, true);
        join(other, &mut bob, &welcome, true);
        let hello = send(creator, &mut alice, "from the creator");
        assert_eq!(read(other, &mut bob, &hello), "from the creator");
        let hello = send(other, &mut bob, "from the other release");
        assert_eq!(read(creator, &mut alice, &hello), "from the other release");

        let (welcome, commit) = add(creator, &mut alice, &carol_key_package, true);
        apply(other, &mut bob, &commit);
        join(other, &mut carol, &welcome, true);
        let three = send(other, &mut carol, "three of us");
        assert_eq!(read(creator, &mut alice, &three), "three of us");
        assert_eq!(read(other, &mut bob, &three), "three of us");
    }
}

/// A state's join configuration under the name the previous release stored it with.
fn with_previous_join_config_name(state: &[u8]) -> Vec<u8> {
    let mut value: Value = serde_json::from_slice(state).expect("a group state");
    for entry in value["storage_map"].as_array_mut().expect("entries") {
        let key: Vec<u8> = serde_json::from_value(entry[0].clone()).expect("key");
        if key.starts_with(b"MlsGroupJoinConfig") {
            let stored: Vec<u8> = serde_json::from_value(entry[1].clone()).expect("value");
            let renamed = String::from_utf8(stored)
                .expect("JSON")
                .replace("\"past_epoch_deletion_policy\"", "\"max_past_epochs\"");
            entry[1] = serde_json::to_value(renamed.into_bytes()).expect("value");
        }
    }
    serde_json::to_vec(&value).expect("a group state")
}

/// The previous release cannot load a group state this one wrote: this release stores the join
/// configuration's retention setting as `past_epoch_deletion_policy`, which the previous release does
/// not read. With that one field under its old name, the previous release loads the state and goes on
/// reading and sending, on both lanes and after commits.
#[test]
fn state_this_release_wrote_loads_under_the_previous_one_only_with_the_old_field_name() {
    for mimi in [false, true] {
        let (_, mut alice) = identity(Current, "alice", mimi);
        let (bob_key_package, mut bob) = identity(Current, "bob", mimi);
        let (carol_key_package, mut carol) = identity(Current, "carol", mimi);
        create(Current, &mut alice, "rollback", mimi);
        let (welcome, _) = add(Current, &mut alice, &bob_key_package, mimi);
        join(Current, &mut bob, &welcome, mimi);
        let (welcome, commit) = add(Current, &mut alice, &carol_key_package, mimi);
        apply(Current, &mut bob, &commit);
        join(Current, &mut carol, &welcome, mimi);
        let first = send(Current, &mut alice, "first");
        assert_eq!(read(Current, &mut bob, &first), "first");
        let in_flight = send(Current, &mut alice, "in flight");

        let refused = call(
            Previous,
            json!({ "op": "members", "state": hex::encode(&bob.state) }),
        );
        assert!(
            refused
                .as_ref()
                .is_err_and(|error| error.contains("SerializationError")),
            "{refused:?}"
        );

        bob.state = with_previous_join_config_name(&bob.state);
        alice.state = with_previous_join_config_name(&alice.state);
        carol.state = with_previous_join_config_name(&carol.state);
        assert_eq!(read(Previous, &mut bob, &in_flight), "in flight");
        let reply = send(Previous, &mut bob, "back on the previous release");
        assert_eq!(
            read(Previous, &mut alice, &reply),
            "back on the previous release"
        );
        assert_eq!(
            read(Previous, &mut carol, &reply),
            "back on the previous release"
        );
    }
}

/// The negative control for the state rows: a previous-release state whose group-state tag is
/// corrupted is refused by this release, so the rows above read the stored state rather than
/// accepting anything.
#[test]
fn a_corrupted_previous_state_is_refused() {
    let (_, mut alice) = identity(Previous, "alice", false);
    create(Previous, &mut alice, "corrupted", false);
    assert!(call(
        Current,
        json!({ "op": "members", "state": hex::encode(&alice.state) })
    )
    .is_ok());

    let mut value: Value = serde_json::from_slice(&alice.state).expect("a group state");
    let mut corrupted = 0;
    for entry in value["storage_map"].as_array_mut().expect("entries") {
        let key: Vec<u8> = serde_json::from_value(entry[0].clone()).expect("key");
        if key.starts_with(b"GroupState") {
            let stored: Vec<u8> = serde_json::from_value(entry[1].clone()).expect("value");
            assert_eq!(stored, b"\"Operational\"");
            entry[1] = serde_json::to_value(b"\"Operationel\"".to_vec()).expect("value");
            corrupted += 1;
        }
    }
    assert_eq!(corrupted, 1);
    let state = serde_json::to_vec(&value).expect("a group state");
    let refused = call(
        Current,
        json!({ "op": "members", "state": hex::encode(&state) }),
    );
    assert!(refused.is_err(), "{refused:?}");
}

const SUBMISSION: &[u8] = b"cross-version submission";

/// A pending commit as the previous release stores it before the first send: (pending, commit,
/// welcome).
fn stage_previous(member: &Member, key_package: &[u8], mimi: bool) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let op = if mimi {
        "mimi_add_member_commit_pending"
    } else {
        "add_member_pending"
    };
    let mut got = ok(
        Previous,
        json!({ "op": op, "state": hex::encode(&member.state), "bundle": hex::encode(&member.bundle),
                "key_package": hex::encode(key_package), "submission": hex::encode(SUBMISSION) }),
    );
    let welcome = got.pop().unwrap();
    let commit = got.pop().unwrap();
    (got.pop().unwrap(), commit, welcome)
}

/// The three pending-commit shapes: a native group and a MIMI group made to send handshakes privately
/// (whose abandon goes through the MLS implementation), and a MIMI group sending them in the clear.
fn pending_lanes() -> [(&'static str, bool, bool); 3] {
    [
        ("native", false, false),
        ("mimi", true, false),
        ("mimi-private", true, true),
    ]
}

/// A group of alice and bob on the previous release, with carol's key package waiting.
fn previous_pair(name: &str, mimi: bool, private: bool) -> (Member, Member, Vec<u8>, Member) {
    let (_, mut alice) = identity(Previous, "alice", mimi);
    let (bob_key_package, mut bob) = identity(Previous, "bob", mimi);
    let (carol_key_package, carol) = identity(Previous, "carol", mimi);
    create(Previous, &mut alice, name, mimi);
    if private {
        alice.state = ok(
            Previous,
            json!({ "op": "mimi_send_handshake_privately", "state": hex::encode(&alice.state),
                    "bundle": hex::encode(&alice.bundle) }),
        )
        .remove(0);
    }
    let (welcome, _) = add(Previous, &mut alice, &bob_key_package, mimi);
    join(Previous, &mut bob, &welcome, mimi);
    (alice, bob, carol_key_package, carol)
}

/// A pending commit the previous release staged and stored before sending is confirmed by this one
/// when the delivery service accepts it, and the successor works with the other members.
#[test]
fn a_pending_commit_the_previous_release_stored_confirms_under_this_one() {
    for (name, mimi, private) in pending_lanes() {
        let (mut alice, mut bob, carol_key_package, mut carol) = previous_pair(name, mimi, private);
        let (pending, commit, welcome) = stage_previous(&alice, &carol_key_package, mimi);

        alice.state = ok(
            Current,
            json!({ "op": "confirm", "pending": hex::encode(&pending), "canonical": hex::encode(&alice.state),
                    "submission": hex::encode(SUBMISSION) }),
        )
        .remove(0);
        apply(Current, &mut bob, &commit);
        join(Current, &mut carol, &welcome, mimi);
        assert_eq!(
            identities(Current, &alice.state),
            ["alice", "bob", "carol"],
            "{name}"
        );
        let everyone = send(Current, &mut alice, "everyone");
        assert_eq!(read(Current, &mut bob, &everyone), "everyone", "{name}");
        assert_eq!(read(Current, &mut carol, &everyone), "everyone", "{name}");
    }
}

/// A pending commit the previous release stored is abandoned by this one to a predecessor-epoch state
/// that goes on working; for a commit sent in the clear it is the stored predecessor, byte for byte.
#[test]
fn a_pending_commit_the_previous_release_stored_abandons_under_this_one() {
    for (name, mimi, private) in pending_lanes() {
        let (mut alice, mut bob, carol_key_package, _) = previous_pair(name, mimi, private);
        let (pending, _, _) = stage_previous(&alice, &carol_key_package, mimi);

        let abandoned = ok(
            Current,
            json!({ "op": "abandon", "pending": hex::encode(&pending) }),
        )
        .remove(0);
        // A native group sends its handshakes privately too; only a clear-text commit restores exactly.
        if mimi && !private {
            assert_eq!(abandoned, alice.state, "{name}");
        }
        alice.state = abandoned;
        assert_eq!(
            identities(Current, &alice.state),
            ["alice", "bob"],
            "{name}"
        );
        let still = send(Current, &mut alice, "still here");
        assert_eq!(read(Current, &mut bob, &still), "still here", "{name}");
    }
}
