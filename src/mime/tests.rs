// Behavior-compat + security tests for `crate::mime::parse`.
//
// Two jobs:
//  (1) BEHAVIOR-COMPAT - every real-world MIME shape a mail client encounters, this
//      parser must accept. This corpus is the cross-language proof any binding layer
//      built on this parser can share.
//  (2) SECURITY - hostile/malformed input must NEVER panic; the depth cap (20)
//      must bound recursion; fail-closed returns a value or a typed error.

use super::*;

const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;

fn b64_lines(bytes: &[u8]) -> String {
    let s = B64.encode(bytes);
    let mut out = String::new();
    let chars: Vec<char> = s.chars().collect();
    for chunk in chars.chunks(76) {
        out.extend(chunk);
        out.push_str("\r\n");
    }
    out
}

// ───────────────────────── behavior-compat ─────────────────────────

#[test]
fn raw_plain_text() {
    let r = parse("Hello world").unwrap();
    assert_eq!(r.body, "Hello world");
    assert!(r.html_body.is_none());
    assert!(r.attachments.is_empty());
}

#[test]
fn mime_version_plain_text() {
    let mime = "MIME-Version: 1.0\r\n\
                Content-Type: text/plain; charset=utf-8\r\n\
                Content-Transfer-Encoding: 8bit\r\n\
                \r\n\
                Hello MIME world";
    let r = parse(mime).unwrap();
    assert_eq!(r.body, "Hello MIME world");
    assert!(r.html_body.is_none());
    assert!(r.attachments.is_empty());
}

#[test]
fn multipart_alternative_html_plus_plain() {
    let mime = "MIME-Version: 1.0\r\n\
                Content-Type: multipart/alternative; boundary=\"haven_pgp_alt_test\"\r\n\
                \r\n\
                --haven_pgp_alt_test\r\n\
                Content-Type: text/plain; charset=utf-8\r\n\
                Content-Transfer-Encoding: 8bit\r\n\
                \r\n\
                Plain body\r\n\
                --haven_pgp_alt_test\r\n\
                Content-Type: text/html; charset=utf-8\r\n\
                Content-Transfer-Encoding: 8bit\r\n\
                \r\n\
                <p>HTML body</p>\r\n\
                --haven_pgp_alt_test--\r\n";
    let r = parse(mime).unwrap();
    assert_eq!(r.body, "Plain body");
    assert!(r.html_body.as_deref().unwrap().contains("<p>HTML body</p>"));
    assert!(r.attachments.is_empty());
}

#[test]
fn multipart_related_inline_image() {
    let payload = [0xDEu8, 0xAD, 0xBE, 0xEF];
    let img = b64_lines(&payload);
    let mime = format!(
        "MIME-Version: 1.0\r\n\
         Content-Type: multipart/related;\r\n\
         \x20   type=\"multipart/alternative\";\r\n\
         \x20   boundary=\"haven_rel_test\"\r\n\
         \r\n\
         --haven_rel_test\r\n\
         Content-Type: multipart/alternative; boundary=\"haven_alt_test\"\r\n\
         \r\n\
         --haven_alt_test\r\n\
         Content-Type: text/plain; charset=utf-8\r\n\
         Content-Transfer-Encoding: 8bit\r\n\
         \r\n\
         See photo\r\n\
         --haven_alt_test\r\n\
         Content-Type: text/html; charset=utf-8\r\n\
         Content-Transfer-Encoding: 8bit\r\n\
         \r\n\
         <p>See <img src=\"cid:img0@haven\"/></p>\r\n\
         --haven_alt_test--\r\n\
         --haven_rel_test\r\n\
         Content-Type: image/jpeg; name=\"image0.jpeg\"\r\n\
         Content-Disposition: inline; filename=\"image0.jpeg\"\r\n\
         Content-ID: <img0@haven>\r\n\
         Content-Transfer-Encoding: base64\r\n\
         \r\n\
         {img}--haven_rel_test--\r\n"
    );
    let r = parse(&mime).unwrap();
    assert_eq!(r.body, "See photo");
    assert!(r.html_body.as_deref().unwrap().contains("cid:img0@haven"));
    assert_eq!(r.attachments.len(), 1);
    let a = &r.attachments[0];
    assert_eq!(a.content_id.as_deref(), Some("img0@haven"));
    assert_eq!(a.filename, "image0.jpeg");
    assert_eq!(a.mime_type, "image/jpeg");
    assert_eq!(a.content, payload);
}

#[test]
fn multipart_mixed_inline_image_plus_attachment() {
    let img_payload = [0x01u8, 0x02, 0x03];
    let pdf_payload = b"%PDF-1.0\n%%%\n";
    let img = b64_lines(&img_payload);
    let pdf = b64_lines(pdf_payload);
    let rel = format!(
        "Content-Type: multipart/related;\r\n\
         \x20   type=\"multipart/alternative\";\r\n\
         \x20   boundary=\"haven_rel_test\"\r\n\
         \r\n\
         --haven_rel_test\r\n\
         Content-Type: multipart/alternative; boundary=\"haven_alt_test\"\r\n\
         \r\n\
         --haven_alt_test\r\n\
         Content-Type: text/plain; charset=utf-8\r\n\
         Content-Transfer-Encoding: 8bit\r\n\
         \r\n\
         See photo and PDF\r\n\
         --haven_alt_test\r\n\
         Content-Type: text/html; charset=utf-8\r\n\
         Content-Transfer-Encoding: 8bit\r\n\
         \r\n\
         <p>See <img src=\"cid:img0@haven\"/></p>\r\n\
         --haven_alt_test--\r\n\
         --haven_rel_test\r\n\
         Content-Type: image/jpeg; name=\"image0.jpeg\"\r\n\
         Content-Disposition: inline; filename=\"image0.jpeg\"\r\n\
         Content-ID: <img0@haven>\r\n\
         Content-Transfer-Encoding: base64\r\n\
         \r\n\
         {img}--haven_rel_test--\r\n"
    );
    let mime = format!(
        "MIME-Version: 1.0\r\n\
         Content-Type: multipart/mixed; boundary=\"haven_outer_test\"\r\n\
         \r\n\
         --haven_outer_test\r\n\
         {rel}\
         --haven_outer_test\r\n\
         Content-Type: application/pdf; name=\"doc.pdf\"\r\n\
         Content-Disposition: attachment; filename=\"doc.pdf\"\r\n\
         Content-Transfer-Encoding: base64\r\n\
         \r\n\
         {pdf}--haven_outer_test--\r\n"
    );
    let r = parse(&mime).unwrap();
    assert_eq!(r.body, "See photo and PDF");
    assert!(r.html_body.as_deref().unwrap().contains("cid:img0@haven"));
    assert_eq!(r.attachments.len(), 2);
    let inline: Vec<_> = r
        .attachments
        .iter()
        .filter(|a| a.content_id.is_some())
        .collect();
    let downloads: Vec<_> = r
        .attachments
        .iter()
        .filter(|a| a.content_id.is_none())
        .collect();
    assert_eq!(inline.len(), 1);
    assert_eq!(downloads.len(), 1);
    assert_eq!(inline[0].filename, "image0.jpeg");
    assert_eq!(inline[0].content, img_payload);
    assert_eq!(downloads[0].filename, "doc.pdf");
    assert_eq!(downloads[0].mime_type, "application/pdf");
    assert_eq!(downloads[0].content, pdf_payload);
}

#[test]
fn lf_only_line_endings() {
    let mime = "MIME-Version: 1.0\n\
                Content-Type: multipart/alternative; boundary=\"b\"\n\
                \n\
                --b\n\
                Content-Type: text/plain; charset=utf-8\n\
                Content-Transfer-Encoding: 8bit\n\
                \n\
                LF body\n\
                --b\n\
                Content-Type: text/html; charset=utf-8\n\
                Content-Transfer-Encoding: 8bit\n\
                \n\
                <p>LF html</p>\n\
                --b--\n";
    let r = parse(mime).unwrap();
    assert_eq!(r.body, "LF body");
    assert!(r.html_body.as_deref().unwrap().contains("<p>LF html</p>"));
}

#[test]
fn folded_content_type_boundary_found() {
    let payload = [0xAAu8, 0xBB];
    let img = b64_lines(&payload);
    let mime = format!(
        "MIME-Version: 1.0\r\n\
         Content-Type: multipart/related;\r\n\
         \x20   type=\"multipart/alternative\";\r\n\
         \x20   boundary=\"folded_rel\"\r\n\
         \r\n\
         --folded_rel\r\n\
         Content-Type: image/jpeg; name=\"image0.jpeg\"\r\n\
         Content-Disposition: inline; filename=\"image0.jpeg\"\r\n\
         Content-ID: <img0@haven>\r\n\
         Content-Transfer-Encoding: base64\r\n\
         \r\n\
         {img}--folded_rel--\r\n"
    );
    let r = parse(&mime).unwrap();
    assert_eq!(r.attachments.len(), 1);
    assert_eq!(r.attachments[0].content_id.as_deref(), Some("img0@haven"));
}

#[test]
fn quoted_printable_text_part() {
    let mime = "Content-Type: text/plain; charset=utf-8\r\n\
                Content-Transfer-Encoding: quoted-printable\r\n\
                \r\n\
                Caf=C3=A9 =E2=82=AC end";
    // single-part path: starts with "Content-Type: text/plain"
    let r = parse(mime).unwrap();
    assert_eq!(r.body, "Café € end");
}

#[test]
fn base64_text_part_round_trips_utf8() {
    let original = "héllo base64 ☕";
    let mime = format!(
        "Content-Type: text/plain; charset=utf-8\r\n\
         Content-Transfer-Encoding: base64\r\n\
         \r\n\
         {}",
        B64.encode(original.as_bytes())
    );
    // multipart-free single part - but `parse` routes non-multipart text/plain
    // via the single-part path only when it starts with the recognized prefix.
    let r = parse(&mime).unwrap();
    assert_eq!(r.body, original);
}

#[test]
fn unsafe_cid_prefix_stripped() {
    let payload = [0x00u8];
    let img = b64_lines(&payload);
    let mime = format!(
        "MIME-Version: 1.0\r\n\
         Content-Type: multipart/related; boundary=\"r\"\r\n\
         \r\n\
         --r\r\n\
         Content-Type: text/html; charset=utf-8\r\n\
         Content-Transfer-Encoding: 8bit\r\n\
         \r\n\
         <img src=\"unsafe:cid:img0@haven\"/>\r\n\
         --r\r\n\
         Content-Type: image/png; name=\"i.png\"\r\n\
         Content-Disposition: inline; filename=\"i.png\"\r\n\
         Content-ID: <img0@haven>\r\n\
         Content-Transfer-Encoding: base64\r\n\
         \r\n\
         {img}--r--\r\n"
    );
    let r = parse(&mime).unwrap();
    let html = r.html_body.unwrap();
    assert!(html.contains("cid:img0@haven"));
    assert!(!html.contains("unsafe:cid:"));
}

#[test]
fn moderate_nesting_still_extracts_body() {
    // 3-deep multipart → the inner text body must still surface.
    let mut inner = "Content-Type: text/plain; charset=utf-8\r\n\r\ndeep body".to_string();
    for i in 0..3 {
        let b = format!("lvl{i}");
        inner = format!(
            "Content-Type: multipart/mixed; boundary=\"{b}\"\r\n\r\n--{b}\r\n{inner}\r\n--{b}--\r\n"
        );
    }
    let r = parse(&inner).unwrap();
    assert_eq!(r.body, "deep body");
}

// ───────────────────────── security / no-panic ─────────────────────────

fn nested_bomb(levels: usize) -> String {
    let mut inner = "Content-Type: text/plain; charset=utf-8\r\n\r\ndeep".to_string();
    for i in 0..levels {
        let b = format!("b{i}");
        inner = format!(
            "Content-Type: multipart/mixed; boundary=\"{b}\"\r\n\r\n--{b}\r\n{inner}\r\n--{b}--\r\n"
        );
    }
    inner
}

#[test]
fn deep_nesting_bomb_does_not_overflow() {
    // 200 levels - far past the depth cap. Must RETURN (no stack overflow / panic).
    let bomb = nested_bomb(200);
    let r = parse(&bomb);
    assert!(r.is_ok());
}

/// An amplification-shaped bomb: a large inner body nested
/// through many multipart levels. Before the fix, EVERY level re-embedded the entire remaining
/// (still-large) body into a freshly `format!`-allocated String before recursing, so N levels
/// near the input cap retained N near-full-size temporary strings simultaneously (~1.25 GiB from
/// a 64 MiB payload nested 20 deep). This test can't instrument peak-RSS from inside the crate
/// (no allocator introspection here), so it asserts what IS testable from this API: the parse
/// actually COMPLETES and returns the correct inner content - the borrowed-slice fix makes total
/// allocation `O(input size)` instead of `O(depth × input size)`, so a multi-MB inner body nested
/// to (just under) the depth cap must not be materially slower than a tiny one at the same depth.
#[test]
fn large_body_nested_nineteen_levels_completes_with_correct_content() {
    // 19 levels (one below MAX_MIME_DEPTH=20, so the real multipart-walk path runs the whole way,
    // not the depth-cap bail) around a 4 MiB inner text body - large enough that the OLD
    // O(depth × size) behavior would have been clearly, not marginally, more expensive.
    let big = "A".repeat(4 * 1024 * 1024);
    let mut inner = format!("Content-Type: text/plain; charset=utf-8\r\n\r\n{big}");
    for i in 0..19 {
        let b = format!("amp{i}");
        inner = format!(
            "Content-Type: multipart/mixed; boundary=\"{b}\"\r\n\r\n--{b}\r\n{inner}\r\n--{b}--\r\n"
        );
    }
    let start = std::time::Instant::now();
    let r = parse(&inner).expect("must parse, not TooLarge (well under MAX_INPUT_BYTES)");
    let elapsed = start.elapsed();
    assert_eq!(r.body.len(), big.len(), "inner body must survive intact");
    assert_eq!(r.body, big);
    // Generous ceiling (not a tight perf assertion, CI hosts vary) - a few seconds, not the
    // many-seconds-to-OOM shape the O(depth×size) allocation pattern produced at this size.
    assert!(
        elapsed.as_secs() < 10,
        "19-level parse of a 4 MiB body took {elapsed:?} - suggests the amplification regressed"
    );
}

/// Width cap: a single multipart level with far more parts than `MAX_MIME_PARTS`
/// must not silently degrade to a partial `Ok` - the caller loses provenance of which parts
/// were dropped, so `parse` now returns `Err(MimeError::Truncated)` instead.
#[test]
fn wide_multipart_hits_the_part_cap() {
    let boundary = "wide";
    let mut body = String::new();
    let total_parts = crate::mime::MAX_MIME_PARTS + 500;
    for i in 0..total_parts {
        body.push_str(&format!(
            "--{boundary}\r\nContent-Type: application/octet-stream; name=\"p{i}\"\r\nContent-Disposition: attachment; filename=\"p{i}\"\r\n\r\nx\r\n"
        ));
    }
    body.push_str(&format!("--{boundary}--\r\n"));
    let mime = format!("Content-Type: multipart/mixed; boundary=\"{boundary}\"\r\n\r\n{body}");

    let r = parse(&mime);
    assert!(
        matches!(r, Err(crate::mime::MimeError::Truncated)),
        "a multipart body over MAX_MIME_PARTS must return Err(Truncated), got {r:?}"
    );
}

/// The under-cap sibling of `wide_multipart_hits_the_part_cap`: a part count at (not over) the
/// cap parses normally, proving the truncation check doesn't false-positive on a legitimate
/// (if unusually wide) message.
#[test]
fn multipart_at_the_part_cap_does_not_truncate() {
    let boundary = "atcap";
    let mut body = String::new();
    let total_parts = crate::mime::MAX_MIME_PARTS;
    for i in 0..total_parts {
        body.push_str(&format!(
            "--{boundary}\r\nContent-Type: application/octet-stream; name=\"p{i}\"\r\nContent-Disposition: attachment; filename=\"p{i}\"\r\n\r\nx\r\n"
        ));
    }
    body.push_str(&format!("--{boundary}--\r\n"));
    let mime = format!("Content-Type: multipart/mixed; boundary=\"{boundary}\"\r\n\r\n{body}");

    let r = parse(&mime).expect("a part count at (not over) the cap must not truncate");
    assert_eq!(r.attachments.len(), total_parts);
}

#[test]
fn malformed_inputs_never_panic() {
    let hostile: Vec<String> = vec![
        String::new(),
        "Content-Type: multipart/mixed".to_string(), // no boundary
        "Content-Type: multipart/mixed; boundary=\"b\"".to_string(), // boundary, no parts
        "Content-Type: multipart/mixed; boundary=\"b\"\r\n\r\n--b\r\n".to_string(), // truncated part
        "MIME-Version: 1.0".to_string(),             // header only, no body sep
        "Content-Type: text/plain".to_string(),
        "=========".to_string(),
        "Content-Type: application/pdf; name=\"x\"\r\nContent-Transfer-Encoding: base64\r\n\r\n!!!not base64!!!".to_string(),
        "Content-Type: multipart/mixed; boundary=\"\"\r\n\r\n----\r\n".to_string(), // empty boundary
        "\r\n\r\n\r\n\r\n".to_string(),
        "Content-Type: multipart/mixed; boundary=\"b\"\r\n\r\n--b\r\nContent-Type: text/plain\r\n\r\n".to_string(),
        "Content-Type: multipart/mixed; boundary=b\r\n\r\n--b\r\nContent-Type: image/png; filename=q\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\n=X=Y=ZZ==\r\n--b--".to_string(),
    ];
    for h in &hostile {
        // Must not panic; result is accepted whatever it is.
        let _ = parse(h);
    }
    // A pseudo-random byte smear (deterministic) must also not panic.
    let mut s = String::new();
    let mut x: u32 = 0x1234_5678;
    for _ in 0..50_000 {
        x = x.wrapping_mul(1_103_515_245).wrapping_add(12_345);
        let c = ((x >> 16) & 0x7f) as u8;
        s.push(c as char);
    }
    let _ = parse(&s);
}

// ───────────────────────── RFC-3156 envelope builder ─────────────────────────

#[test]
fn pgp_envelope_structure_octet_stream_part_is_bare() {
    let payload = "-----BEGIN PGP MESSAGE-----\r\nabc\r\n-----END PGP MESSAGE-----";
    let env = build_pgp_envelope(payload);
    assert!(env.starts_with("Content-Type: multipart/encrypted;"));
    assert!(env.contains("protocol=\"application/pgp-encrypted\""));
    assert!(env.contains("Content-Type: application/pgp-encrypted\r\n\r\nVersion: 1\r\n"));
    assert!(env.contains("Content-Type: application/octet-stream\r\n\r\n"));
    // the octet-stream part MUST be bare - no name=, no Content-Disposition.
    assert!(!env.contains("name="));
    assert!(!env.to_lowercase().contains("content-disposition"));
    assert!(env.contains(payload));
    assert!(env.trim_end().ends_with("--"));
}

#[test]
fn pgp_envelope_payload_crlf_idempotent() {
    // A payload already ending in CRLF must not produce a double blank line; one
    // not ending in CRLF gets exactly one added - both land at `X\r\n\r\n--`.
    assert!(build_pgp_envelope("X\r\n").contains("X\r\n\r\n--"));
    assert!(build_pgp_envelope("X").contains("X\r\n\r\n--"));
}

#[test]
fn bad_base64_attachment_skipped_not_panicked() {
    let mime = "Content-Type: multipart/mixed; boundary=\"b\"\r\n\
                \r\n\
                --b\r\n\
                Content-Type: application/octet-stream; name=\"x.bin\"\r\n\
                Content-Disposition: attachment; filename=\"x.bin\"\r\n\
                Content-Transfer-Encoding: base64\r\n\
                \r\n\
                @@@not-valid-base64@@@\r\n\
                --b--\r\n";
    // multipart but the only part is an undecodable base64 attachment → treated
    // as absent → skipped. No panic; zero attachments.
    let r = parse(mime).unwrap();
    assert!(r.attachments.is_empty());
}

// ───────── RFC-2047 outer-header encoders - mirrors the client's own encoding test suite ─────────
//
// The client's own header-encoding test suite is the byte-identity spec; these are
// the SAME cases against the Rust port. A divergence here = a wire-format regression.

/// Decode an RFC-2047 value back to the original (test oracle): concatenate the
/// B-encoded words' UTF-8, pass ASCII through. Mirrors the client's own test decoder.
fn decode2047(header: &str) -> String {
    if !header.contains("=?") {
        return header.to_string();
    }
    let mut out: Vec<u8> = Vec::new();
    let mut rest = header;
    while let Some(start) = rest.find("=?UTF-8?B?") {
        // Whitespace BETWEEN adjacent encoded-words is not significant (RFC 2047 §6.2).
        let between = &rest[..start];
        if !between.trim().is_empty() {
            out.extend_from_slice(between.as_bytes());
        }
        let after = &rest[start + "=?UTF-8?B?".len()..];
        let end = after.find("?=").expect("well-formed encoded-word");
        out.extend_from_slice(&B64.decode(after[..end].as_bytes()).expect("valid b64"));
        rest = &after[end + 2..];
    }
    if !rest.is_empty() {
        out.extend_from_slice(rest.as_bytes());
    }
    String::from_utf8(out).expect("valid utf8")
}

#[test]
fn enc_header_ascii_passthrough_byte_identical() {
    let s = "Plain ASCII subject (2 attachments)";
    assert_eq!(encode_header_word(s), s);
}

#[test]
fn enc_header_emdash_b_encoded_and_roundtrips() {
    let s = "Forward-test fixture — try forwarding me";
    let enc = encode_header_word(s);
    assert!(enc.starts_with("=?UTF-8?B?"));
    assert!(!enc.contains('—')); // no raw non-ASCII left
    assert_eq!(decode2047(&enc), s);
}

#[test]
fn enc_header_accents_emoji_roundtrip() {
    let s = "Réçu façturé 🔒 — Haven";
    assert_eq!(decode2047(&encode_header_word(s)), s);
}

#[test]
fn enc_header_crlf_stripped() {
    let enc = encode_header_word("a\r\nBcc: evil@x — b");
    assert!(!enc.contains('\r'));
    assert!(!enc.contains('\n'));
    assert_eq!(decode2047(&enc), "a  Bcc: evil@x — b"); // CR→space, LF→space (two spaces)
}

#[test]
fn enc_header_long_nonascii_words_le75_lines_le78_roundtrips() {
    let s = format!("Café {} ω end", "数".repeat(60));
    let enc = encode_header_word(&s);
    for line in enc.split("\r\n") {
        assert!(line.len() <= 78, "unfolded line >78: {line}");
        for word in line.trim().split(' ') {
            assert!(word.len() <= 75, "word >75: {word}");
        }
    }
    assert_eq!(decode2047(&enc), s);
}

#[test]
fn enc_header_long_nonascii_is_folded() {
    let s = format!("Préface {} fin", "é".repeat(120));
    let enc = encode_header_word(&s);
    assert!(enc.contains("\r\n "), "must fold, not one 600+ char line");
    for line in enc.split("\r\n") {
        assert!(line.len() <= 78);
    }
    assert_eq!(decode2047(&enc), s);
}

#[test]
fn enc_header_long_ascii_folded_on_whitespace() {
    let s = (0..40)
        .map(|i| format!("word{i}"))
        .collect::<Vec<_>>()
        .join(" ");
    let enc = encode_header_word(&s);
    assert!(enc.contains("\r\n "));
    for line in enc.split("\r\n") {
        assert!(line.len() <= 78);
    }
    // Folding is whitespace-only: unfold (CRLF+SP → single space) == original.
    assert_eq!(enc.replace("\r\n ", " "), s);
}

#[test]
fn enc_addr_bare_ascii_unchanged() {
    assert_eq!(encode_address_header("a@b.com"), "a@b.com");
}

#[test]
fn enc_addr_ascii_display_name_unchanged() {
    let v = "\"Test User\" <test@example.com>";
    assert_eq!(encode_address_header(v), v);
}

#[test]
fn enc_addr_nonascii_phrase_encoded_spec_untouched() {
    let enc = encode_address_header("\"José\" <jose@havenmessenger.com>");
    assert!(enc.contains("<jose@havenmessenger.com>"));
    assert!(enc.starts_with("=?UTF-8?B?"));
    assert!(!enc.contains('é'));
    let phrase = &enc[..enc.find(" <").expect("space-lt")];
    assert_eq!(decode2047(phrase), "José"); // quotes stripped before encoding
}

#[test]
fn enc_addr_list_quote_aware_comma_split() {
    let enc = encode_address_header("\"Smith, John\" <john@x.com>, \"Zoë\" <zoe@x.com>");
    // Two recipients survive (the comma inside "Smith, John" is not a separator).
    assert_eq!(enc.matches('<').count(), 2);
    assert!(enc.contains("<john@x.com>"));
    assert!(enc.contains("<zoe@x.com>"));
}

#[test]
fn enc_addr_long_list_folds_addr_specs_intact() {
    let v = (0..12)
        .map(|i| format!("\"Person Number {i}\" <user{i}@example.com>"))
        .collect::<Vec<_>>()
        .join(", ");
    let enc = encode_address_header(&v);
    for line in enc.split("\r\n") {
        assert!(line.len() <= 78, "unfolded line: {line}");
    }
    for i in 0..12 {
        assert!(enc.contains(&format!("<user{i}@example.com>")));
    }
}

// ───────── Full outer assembly + inner related-wrap ─────────

#[test]
fn outer_mime_canonical_header_order_ascii_passthrough() {
    let body = build_pgp_envelope("-----BEGIN PGP MESSAGE-----\n\nXX==\n-----END PGP MESSAGE-----");
    let routing = OuterRouting {
        from: "Haven <welcome@havenmessenger.com>".into(),
        to: "alice@example.com".into(),
        subject: "Welcome to Haven".into(),
        date: "Tue, 30 Jun 2026 22:00:00 +0000".into(),
        message_id: "<abc@havenmessenger.com>".into(),
        ..Default::default()
    };
    let extra = vec![
        ("Auto-Submitted".to_string(), "auto-generated".to_string()),
        ("X-Mailer".to_string(), "Haven".to_string()),
    ];
    let msg = build_full_outer_mime(&body, &routing, &extra);
    // Canonical order: MIME-Version → From → To → Subject → Date → Message-ID → extras → body.
    let pos = |needle: &str| {
        msg.find(needle)
            .unwrap_or_else(|| panic!("missing: {needle}"))
    };
    let order = [
        pos("MIME-Version: 1.0"),
        pos("From: Haven <welcome@havenmessenger.com>"),
        pos("To: alice@example.com"),
        pos("Subject: Welcome to Haven"),
        pos("Date: Tue, 30 Jun 2026"),
        pos("Message-ID: <abc@havenmessenger.com>"),
        pos("Auto-Submitted: auto-generated"),
        pos("X-Mailer: Haven"),
        pos("Content-Type: multipart/encrypted"),
    ];
    assert!(
        order.windows(2).all(|w| w[0] < w[1]),
        "header order wrong: {order:?}"
    );
    // All-ASCII headers are byte-identical (no encoded-words emitted).
    assert!(!msg.contains("=?UTF-8?B?"));
}

#[test]
fn outer_mime_nonascii_subject_and_from_phrase_encoded() {
    let body = build_pgp_envelope("CT");
    let routing = OuterRouting {
        from: "\"José\" <jose@x.com>".into(),
        to: "alice@example.com".into(),
        subject: "Réçu — Haven".into(),
        date: "D".into(),
        message_id: "<m>".into(),
        ..Default::default()
    };
    let msg = build_full_outer_mime(&body, &routing, &[]);
    assert!(msg.contains("Subject: =?UTF-8?B?"));
    assert!(msg.contains("<jose@x.com>")); // addr-spec untouched
    assert!(msg.contains("To: alice@example.com")); // ASCII addr untouched
                                                    // No raw non-ASCII anywhere (the body is ASCII PGP); mojibake class closed.
    assert!(!msg.contains('é') && !msg.contains('—') && !msg.contains('ç'));
}

#[test]
fn header_injection_crlf_stripped_from_every_value() {
    let body = build_pgp_envelope("CT");
    let routing = OuterRouting {
        from: "evil@x.com\r\nBcc: victim1@y.com".into(), // bare addr w/ CRLF
        to: "\"N\" <a@b.com>\r\nBcc: victim2@y.com".into(), // display-name addr w/ CRLF
        subject: "Hi\r\nBcc: victim3@y.com".into(),
        date: "D\r\nInjDate: 1".into(),
        message_id: "<m>\r\nInjMid: 1".into(),
        in_reply_to: Some("<irt>\r\nInjIrt: 1".into()),
        references: Some("<ref>\r\nInjRef: 1".into()),
        cc: None,
    };
    let extra = vec![("X-Test".to_string(), "v\r\nInjExtra: 1".to_string())];
    let msg = build_full_outer_mime(&body, &routing, &extra);
    let header_block = &msg[..msg.find("\r\n\r\n").expect("header/body sep")];
    // NO injected header may appear at the start of any header line.
    for inj in [
        "Bcc:",
        "InjDate:",
        "InjMid:",
        "InjIrt:",
        "InjRef:",
        "InjExtra:",
    ] {
        for line in header_block.split("\r\n") {
            assert!(
                !line.trim_start().starts_with(inj),
                "header injection: a line starts with {inj:?}: {line:?}"
            );
        }
    }
    // And the value collapses onto ONE line (CR→space + LF→space = two spaces),
    // so the injected "Bcc:" is inert text inside the From value, not a new header.
    assert!(msg.contains("From: evil@x.com  Bcc: victim1@y.com\r\n"));
}

#[test]
fn related_html_wrap_has_type_param_and_roundtrips() {
    let html = "<html><body>Hi &mdash; welcome</body></html>";
    let block = build_related_html(html);
    assert!(block.contains("Content-Type: multipart/related"));
    assert!(block.contains("type=\"text/html\"")); // RFC 2387 §3.1 required param
    assert!(block.starts_with("MIME-Version: 1.0\r\n")); // client decrypt-parser recognises it
                                                         // Our own parser recovers the HTML (trailing CRLF added by the wrap).
    let parsed = parse(&block).unwrap();
    let recovered = parsed.html_body.expect("html_body present");
    assert_eq!(recovered.trim_end_matches("\r\n"), html);
}
