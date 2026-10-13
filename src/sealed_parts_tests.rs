use super::*;
use crate::suite_policy::{sealed_parts_suite, sealed_parts_suite_from_id};

const PREFIX: [u8; 7] = [0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7];
const DATA: &[u8] = b"example-stream";

fn key() -> Vec<u8> {
    (0x40u8..0x60).collect()
}

fn stream() -> SealedParts {
    SealedParts::new(sealed_parts_suite(), &key(), &PREFIX)
        .expect("a stream of the suite's lengths")
}

fn hex(text: &str) -> Vec<u8> {
    hex::decode(text).expect("hex")
}

/// Three parts of unequal length, the third sealed as the last.
fn three_parts() -> (Vec<Vec<u8>>, Vec<Vec<u8>>) {
    let plain = vec![vec![0x11; 40], vec![0x22; 40], vec![0x33; 9]];
    let sealed = plain
        .iter()
        .zip(0u32..)
        .map(|(part, position)| {
            stream()
                .seal_part(position, position == 2, DATA, part)
                .expect("seals")
        })
        .collect();
    (plain, sealed)
}

/// Sealed bytes computed outside this crate: AES-256-GCM from Python's `cryptography` package under
/// the same key, with each nonce written out by hand as the prefix, the position as four big-endian
/// bytes and the last-part byte. They pin the nonce layout byte for byte.
#[test]
fn sealed_parts_match_answers_from_a_second_implementation() {
    let later: &[u8] = b"the quick brown fox jumps over the lazy dog";
    let ascending: Vec<u8> = (0u8..48).collect();
    let cases: [(u32, bool, &[u8], &[u8], &str); 4] = [
        (
            0,
            false,
            DATA,
            &ascending,
            "06cfb35f4f46d527b4b2911c0e77ee65bd900934795520dc3af7c58102341dd5ecdfa51b2961d5fb93c4d1cf\
             77abeea835b95d2a12db55cd8952f7f93f57580b",
        ),
        (
            0x0102_0304,
            false,
            DATA,
            later,
            "e5c882c62ed3f203ef57f2f0b40512cb6441f6e1e602e18c4f7a183c0e502a9ef4338eb93ae1b30dac25af45\
             ad9457a4a6c0d8beac2fc7329949a9",
        ),
        (5, true, DATA, b"tail", "b7fc006dc215f720b4bf26fb6cf8469e5423fed9"),
        (0, true, b"", b"", "2afbe137791b931ce74c1ca7e18baa3c"),
    ];
    for (position, last, data, plain, expected) in cases {
        let expected = hex(&expected.replace(' ', ""));
        assert_eq!(
            stream()
                .seal_part(position, last, data, plain)
                .expect("seals"),
            expected,
            "part {position} (last: {last}) does not seal to the known answer"
        );
        assert_eq!(
            stream()
                .open_part(position, last, data, &expected)
                .expect("opens"),
            plain,
            "the known answer for part {position} does not open to its plaintext"
        );
    }
}

#[test]
fn parts_open_alone_and_in_any_order() {
    let (plain, sealed) = three_parts();
    for position in [2u32, 0, 1] {
        let index = position as usize;
        assert_eq!(sealed[index].len(), plain[index].len() + PART_OVERHEAD);
        assert_eq!(
            stream()
                .open_part(position, position == 2, DATA, &sealed[index])
                .expect("opens alone"),
            plain[index]
        );
    }
}

#[test]
fn a_missing_part_is_refused_where_the_next_one_arrives_in_its_place() {
    let (_, sealed) = three_parts();
    assert!(stream().open_part(1, false, DATA, &sealed[2]).is_err());
    assert!(stream().open_part(1, true, DATA, &sealed[2]).is_err());
}

#[test]
fn a_repeated_part_is_refused_at_the_next_position() {
    let (_, sealed) = three_parts();
    assert!(stream().open_part(1, false, DATA, &sealed[0]).is_err());
}

#[test]
fn reordered_parts_are_refused_at_both_positions() {
    let (_, sealed) = three_parts();
    assert!(stream().open_part(0, false, DATA, &sealed[1]).is_err());
    assert!(stream().open_part(1, false, DATA, &sealed[0]).is_err());
}

/// A stream cut after its second part: the reader, told the stream has two parts, opens the second
/// as the last, and it was not sealed as the last.
#[test]
fn a_stream_cut_short_is_refused_at_its_new_end() {
    let (_, sealed) = three_parts();
    assert!(stream().open_part(1, true, DATA, &sealed[1]).is_err());
}

#[test]
fn the_last_part_does_not_open_as_an_inner_part() {
    let (_, sealed) = three_parts();
    assert!(stream().open_part(2, false, DATA, &sealed[2]).is_err());
}

#[test]
fn another_key_prefix_or_associated_data_opens_nothing() {
    let (_, sealed) = three_parts();
    let mut other_key = key();
    other_key[31] ^= 1;
    let other = SealedParts::new(sealed_parts_suite(), &other_key, &PREFIX).expect("builds");
    assert!(other.open_part(0, false, DATA, &sealed[0]).is_err());
    let mut other_prefix = PREFIX;
    other_prefix[0] ^= 1;
    let other = SealedParts::new(sealed_parts_suite(), &key(), &other_prefix).expect("builds");
    assert!(other.open_part(0, false, DATA, &sealed[0]).is_err());
    assert!(stream()
        .open_part(0, false, b"another-stream", &sealed[0])
        .is_err());
}

#[test]
fn a_changed_byte_anywhere_in_a_part_is_refused() {
    let (_, sealed) = three_parts();
    for index in [0, sealed[0].len() / 2, sealed[0].len() - 1] {
        let mut changed = sealed[0].clone();
        changed[index] ^= 0x01;
        assert!(
            stream().open_part(0, false, DATA, &changed).is_err(),
            "byte {index} was changed and the part still opened"
        );
    }
}

#[test]
fn a_part_shorter_than_its_tag_is_refused() {
    assert!(stream()
        .open_part(0, true, DATA, &[0u8; PART_OVERHEAD - 1])
        .is_err());
    assert!(stream().open_part(0, true, DATA, &[]).is_err());
}

#[test]
fn the_highest_position_seals_and_opens() {
    let sealed = stream()
        .seal_part(u32::MAX, true, DATA, b"end")
        .expect("seals");
    assert_eq!(
        stream()
            .open_part(u32::MAX, true, DATA, &sealed)
            .expect("opens"),
        b"end"
    );
    assert!(stream()
        .open_part(u32::MAX - 1, true, DATA, &sealed)
        .is_err());
}

#[test]
fn a_key_or_prefix_of_another_length_is_refused() {
    let suite = sealed_parts_suite();
    assert!(SealedParts::new(suite, &key()[..31], &PREFIX).is_err());
    assert!(SealedParts::new(suite, &[key(), vec![0]].concat(), &PREFIX).is_err());
    assert!(SealedParts::new(suite, &key(), &PREFIX[..6]).is_err());
    assert!(SealedParts::new(suite, &key(), &[0u8; 8]).is_err());
}

#[test]
fn a_stream_names_its_suite_by_id_and_an_unknown_id_is_refused() {
    for suite in crate::suite_policy::SealedPartsSuite::ALL {
        assert_eq!(
            sealed_parts_suite_from_id(suite.id()).expect("a known id"),
            suite
        );
    }
    assert_eq!(sealed_parts_suite().id(), 1);
    assert!(sealed_parts_suite_from_id(0).is_err());
    assert!(sealed_parts_suite_from_id(2).is_err());
}
