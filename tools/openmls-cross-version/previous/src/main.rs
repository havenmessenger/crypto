//! Runs one crypto-core operation per invocation: a JSON request on stdin, a JSON answer on stdout.
//! Byte strings travel as hex. An operation that fails answers `{"err": "<text>"}` and exits 0, so the
//! caller can assert on a refusal as on a result.

use std::io::Read;

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

fn bytes(request: &Value, field: &str) -> Vec<u8> {
    hex::decode(request[field].as_str().expect(field)).expect(field)
}

fn text(request: &Value, field: &str) -> String {
    request[field].as_str().expect(field).to_owned()
}

fn answer(parts: &[&[u8]]) -> Value {
    json!({ "ok": parts.iter().map(hex::encode).collect::<Vec<_>>() })
}

fn run(request: &Value) -> anyhow::Result<Value> {
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
        other => anyhow::bail!("unknown operation {other}"),
    })
}

fn main() {
    let mut input = String::new();
    std::io::stdin().read_to_string(&mut input).expect("stdin");
    let request: Value = serde_json::from_str(&input).expect("a JSON request");
    let answer = run(&request).unwrap_or_else(|error| json!({ "err": format!("{error:#}") }));
    println!("{answer}");
}
