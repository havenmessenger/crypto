#![allow(deprecated)] // the byte-in/byte-out functions build the real states these tests read

use super::*;
use crate::identity::generate_identity;
use crate::mls::groups::{add_members_bulk, create_group};
use crate::mls::store::decode_state;

fn round_trip(text: &str) {
    let stored = encode_value(text.as_bytes());
    let back = decode_value(&stored).unwrap();
    assert_eq!(String::from_utf8_lossy(&back), text, "stored as {stored:?}");
}

#[test]
fn compact_json_comes_back_byte_for_byte() {
    for text in [
        "null",
        "true",
        "false",
        "0",
        "7",
        "255",
        "256",
        "18446744073709551615",
        "-1",
        "-9223372036854775808",
        "1.5",
        "1e9",
        "-0",
        "007",
        "\"\"",
        "\"plain\"",
        "\"esc \\\" \\\\ \\n \\u00e9 é\"",
        "[]",
        "{}",
        "[1,2,3]",
        "[0,127,128,200,255]",
        "[0,127,128,200,256]",
        "[1,\"a\",null,[2,3],{\"k\":4}]",
        "{\"a\":[1,2,3],\"b\":{\"c\":\"d\",\"e\":[]},\"f\":-5,\"g\":2.5}",
        "{\"vec\":[36,116,141,255,230,158,0,1]}",
    ] {
        round_trip(text);
    }
}

#[test]
fn text_it_cannot_reproduce_exactly_is_kept_as_text() {
    for text in [
        " [1, 2]",
        "[1, 2]",
        "{\"a\": 1}",
        "not json at all",
        "",
        "[1,2,",
        "{\"a\":1}x",
        "[1,2]]",
        "{1:2}",
    ] {
        let stored = encode_value(text.as_bytes());
        assert_eq!(stored[0], FORM_RAW, "{text:?}");
        assert_eq!(decode_value(&stored).unwrap().as_slice(), text.as_bytes());
    }
}

#[test]
fn a_value_written_before_this_form_is_read_as_text() {
    assert_eq!(
        decode_value(b"{\"a\":[1,2]}").unwrap().as_slice(),
        b"{\"a\":[1,2]}"
    );
    assert_eq!(decode_value(b"[1,2,3]").unwrap().as_slice(), b"[1,2,3]");
}

#[test]
fn byte_strings_cost_a_byte_each() {
    let text = format!(
        "[{}]",
        (0..=255u16)
            .map(|b| b.to_string())
            .collect::<Vec<_>>()
            .join(",")
    );
    let stored = encode_value(text.as_bytes());
    assert!(
        stored.len() <= 256 + 5,
        "{} bytes for 256 bytes",
        stored.len()
    );
    round_trip(&text);
}

#[test]
fn deeply_nested_text_is_kept_as_text_and_never_overflows() {
    let deep = format!("{}1{}", "[".repeat(5000), "]".repeat(5000));
    let stored = encode_value(deep.as_bytes());
    assert_eq!(stored[0], FORM_RAW);
    assert_eq!(decode_value(&stored).unwrap().as_slice(), deep.as_bytes());
}

#[test]
fn a_damaged_stored_value_is_refused_without_panicking() {
    let good = encode_value(b"{\"a\":[1,2,300],\"b\":\"text\",\"c\":[[1],[2]]}");
    assert!(decode_value(&good).is_ok());
    for cut in 1..good.len() {
        // every proper prefix either decodes to something or is refused; none may panic
        let _ = decode_value(&good[..cut]);
    }
    let mut state = 0x9E37_79B9_7F4A_7C15u64;
    for _ in 0..2000 {
        let mut bytes = good.clone();
        for _ in 0..3 {
            state = state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            let at = (state >> 33) as usize % bytes.len();
            bytes[at] = (state >> 20) as u8;
        }
        let _ = decode_value(&bytes);
    }
    assert!(decode_value(&[
        FORM_BINARY,
        BYTES,
        0xff,
        0xff,
        0xff,
        0xff,
        0xff,
        0xff,
        0xff,
        0xff,
        0x7f
    ])
    .is_err());
    assert!(decode_value(&[FORM_BINARY, 0x7e]).is_err());
    assert!(decode_value(&[FORM_BINARY, NULL, NULL]).is_err());
}

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_secs() as i64
}

#[test]
fn every_value_a_real_group_stores_comes_back_exactly_and_much_smaller() {
    let (_, _, founder) = generate_identity("founder".into(), now()).unwrap();
    let mut state = create_group("codec".into(), founder.clone()).unwrap();
    for batch in 0..4 {
        let mut packages = Vec::new();
        for n in 0..5 {
            let (_, package, _) = generate_identity(format!("m{batch}-{n}"), now()).unwrap();
            packages.push(package);
        }
        state = add_members_bulk(state, founder.clone(), packages)
            .unwrap()
            .0;
    }
    let (_, entries) = decode_state(&state).unwrap();
    let mut text = 0usize;
    let mut stored = 0usize;
    for (key, value) in &entries {
        let encoded = encode_value(value);
        assert_eq!(
            encoded[0], FORM_BINARY,
            "a value openmls wrote is compact json"
        );
        assert_eq!(
            decode_value(&encoded).unwrap().as_slice(),
            value.as_slice(),
            "{key:?}"
        );
        text += value.len();
        stored += encoded.len();
    }
    eprintln!(
        "21 members: {text} bytes of json text, {stored} stored ({:.1}x)",
        text as f64 / stored as f64
    );
    assert!(
        stored * 3 <= text,
        "json {text} bytes, stored {stored} bytes: expected at least 3x"
    );
}

#[test]
#[ignore = "inspection"]
fn show_where_the_bytes_are() {
    let (_, _, founder) = generate_identity("founder".into(), now()).unwrap();
    let mut state = create_group("codec".into(), founder.clone()).unwrap();
    let mut packages = Vec::new();
    for n in 0..3 {
        let (_, package, _) = generate_identity(format!("m{n}"), now()).unwrap();
        packages.push(package);
    }
    state = add_members_bulk(state, founder.clone(), packages)
        .unwrap()
        .0;
    let (_, entries) = decode_state(&state).unwrap();
    for (key, value) in &entries {
        let label: String = key
            .iter()
            .take_while(|b| b.is_ascii_alphabetic())
            .map(|b| *b as char)
            .collect();
        if label == "Tree" {
            let text = String::from_utf8_lossy(value);
            eprintln!(
                "Tree json {} bytes, stored {}:\n{}",
                value.len(),
                encode_value(value).len(),
                &text[..text.len().min(1800)]
            );
        } else {
            eprintln!(
                "{label}: json {} stored {}",
                value.len(),
                encode_value(value).len()
            );
        }
    }
}
