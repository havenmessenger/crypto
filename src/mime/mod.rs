// ═══════════════════════════════════════════════════════════════════
// crate::mime - Haven's MIME parser + RFC-3156 envelope builder, in Rust.
//
// WHY (the headline security property): The DECRYPTED inner MIME of an encrypted
//   message is ATTACKER-AUTHORED (it is the plaintext the sender chose to encrypt).
//   Parsing untrusted MIME is historically where email clients earn CVEs - malformed
//   multipart, bad encodings, nesting bombs. This module is a memory-safe, FAIL-CLOSED,
//   depth-capped parser that **never panics on hostile input** (the whole
//   security point): every path returns a typed `Result`/value, the depth cap
//   is enforced *before* recursing, and there is no
//   `unwrap`/`expect`/panicking-index on caller-supplied bytes.
//
// SPEC: RFC 2045 (CTE: base64 / quoted-printable / 7bit/8bit), RFC 2046
//   (multipart boundaries, multipart/{mixed,alternative,related}), RFC 2047
//   (header encoding - builder side), RFC 2387 (multipart/related type=),
//   RFC 3156 §4 (multipart/encrypted envelope - builder side).
//
// PORTING NOTE (behavior-compat is the contract): "accept everything a real client
//   accepts" is the behavior spec this module is held to. It ports the ALGORITHM, not
//   an index-arithmetic detail of any prior implementation: every split is on an ASCII
//   delimiter and every output is a whole logical substring, so the OUTPUT (body /
//   html_body / attachment bytes) is stable across encodings - proven by a dedicated
//   behavior-compat test corpus.
//
// LAYERING: this module is PURE - zero flutter_rust_bridge, zero secrets, zero
//   closed-crate deps - so the SAME crate is reusable by any consumer (a backend
//   CLI, a native app, or any other binding layer). Nothing in this module depends on
//   how a caller exposes it.
// ═══════════════════════════════════════════════════════════════════

use base64::Engine as _;

/// Hard cap on MIME nesting depth. Mirrors the Dart `_maxMimeDepth = 20`
/// without it a crafted deeply-nested `multipart/*` recurses to a
/// stack overflow. Real mail nests ≤3-4 deep; 20 is far beyond legitimate use.
/// Enforced at the TOP of [`parse_mime_entity`], before any further recursion.
pub const MAX_MIME_DEPTH: usize = 20;

/// Defensive cap on total decrypted-MIME input size (spirit - block
/// memory-amplification on a giant hostile plaintext). 64 MiB is far above any
/// legitimate message (Postfix caps the wire at 10 MB). Exceeding it is the one
/// genuine FAIL-CLOSED case → [`MimeError::TooLarge`].
pub const MAX_INPUT_BYTES: usize = 64 * 1024 * 1024;

/// Defensive cap on the number of parts parsed out of ONE `multipart/*` body - width
/// amplification, the sibling concern to the depth cap: a hostile message with thousands of tiny
/// parts at a single nesting level costs one `MimeAttachment`/`String` allocation each even though
/// the depth cap doesn't fire. Real mail has single digits to low tens of parts; 4096 is far
/// beyond legitimate use. Enforced in [`parse_multipart_body`]'s loop - a body that exceeds the
/// cap makes [`parse`] return [`MimeError::Truncated`] instead of a partially-parsed `Ok`, so a
/// caller cannot silently lose attachments or body content past the cap.
pub const MAX_MIME_PARTS: usize = 4096;

/// Typed parse error. The parser is lenient about malformed markup structure (it degrades to a
/// raw-text body the same way the client's prior parser did, rather than erroring), so in
/// normal operation `parse` returns `Ok`. `Err` covers the two cases where continuing would
/// silently lose caller-visible content: the size guard ([`MimeError::TooLarge`]) and a
/// multipart body exceeding the part-count cap ([`MimeError::Truncated`]).
#[derive(Debug, thiserror::Error)]
pub enum MimeError {
    #[error("MIME input exceeds the {MAX_INPUT_BYTES}-byte cap")]
    TooLarge,
    #[error(
        "a multipart body exceeded the {MAX_MIME_PARTS}-part cap; parts beyond it were dropped"
    )]
    Truncated,
}

/// The parsed result handed back to the caller: the text body, the optional
/// HTML body, and the decoded attachments (inline images carry a `content_id`).
/// Pure (no FRB) - a thin binding-layer wrapper mirrors this struct across any language
/// boundary a caller needs.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ParsedMessage {
    pub body: String,
    pub html_body: Option<String>,
    pub attachments: Vec<MimeAttachment>,
}

/// A decoded MIME attachment part. `content_id` non-null ⇒ inline (CID) image.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MimeAttachment {
    pub filename: String,
    pub mime_type: String,
    pub content: Vec<u8>,
    pub content_id: Option<String>,
}

/// Internal aggregate while walking parts - mirrors the Dart `_MimeParsed`. `truncated` is set
/// when a nested `parse_multipart_body` call drops parts past [`MAX_MIME_PARTS`] - the
/// caller must learn about the drop, not receive a silently-partial `Ok`.
#[derive(Default)]
struct MimeParsed {
    body: String,
    html_body: Option<String>,
    attachments: Vec<MimeAttachment>,
    truncated: bool,
}

impl MimeParsed {
    /// Mirrors Dart `_MimeParsed.mergeWith`: body = first non-empty; `html_body`
    /// = first set (`??=`); attachments append. `truncated` propagates (any nested
    /// truncation makes the whole result truncated).
    fn merge_with(&mut self, other: Self) {
        if self.body.is_empty() && !other.body.is_empty() {
            self.body = other.body;
        }
        if self.html_body.is_none() {
            self.html_body = other.html_body;
        }
        self.attachments.extend(other.attachments);
        self.truncated |= other.truncated;
    }
}

/// Parse a decrypted MIME (or raw-text) payload into `{ body, html_body,
/// attachments[] }`. Mirrors the NON-JSON branches of the client's own decrypted-
/// payload parser exactly (a separate JSON-draft branch stays in the client - it
/// is a Haven-internal JSON format, not MIME). FAIL-CLOSED + no-panic.
pub fn parse(input: &str) -> Result<ParsedMessage, MimeError> {
    if input.len() > MAX_INPUT_BYTES {
        return Err(MimeError::TooLarge);
    }

    // Branch detection is case-sensitive `contains`/`starts_with` - a faithful
    // port of the Dart dispatch (header VALUE extraction below is
    // case-insensitive, but the top-level branch test is not).
    if input.contains("Content-Type: multipart/") {
        // == Dart `_parseMimePayload` ==
        let parsed = parse_mime_entity(input, 0);
        if parsed.truncated {
            return Err(MimeError::Truncated);
        }
        // strip the `unsafe:cid:` artifact the Quill delta→HTML
        // sanitizer baked into some older sent emails.
        let html = parsed.html_body.map(|h| h.replace("unsafe:cid:", "cid:"));
        Ok(ParsedMessage {
            body: parsed.body,
            html_body: html,
            attachments: parsed.attachments,
        })
    } else if input.starts_with("MIME-Version:") || input.starts_with("Content-Type: text/plain") {
        // == Dart `_parseSinglePartMime` ==
        let p = parse_single_part(input);
        Ok(ParsedMessage {
            body: p.body,
            html_body: p.html_body,
            attachments: p.attachments,
        })
    } else {
        // Raw plain text (legacy / simple path).
        Ok(ParsedMessage {
            body: input.to_string(),
            html_body: None,
            attachments: Vec::new(),
        })
    }
}

/// Mirrors Dart `_parseMimeEntity`: depth-cap bail → opaque single part; find
/// the boundary; none → single part; else walk the multipart body.
fn parse_mime_entity(content: &str, depth: usize) -> MimeParsed {
    if depth >= MAX_MIME_DEPTH {
        // Bail safely (no recursion, no error): treat the over-nested entity as
        // an opaque single part. Matches Dart's behaviour.
        return parse_single_part(content);
    }
    match find_boundary(content) {
        Some(boundary) if !boundary.is_empty() => parse_multipart_body(content, &boundary, depth),
        _ => parse_single_part(content),
    }
}

/// The borrowed-slice sibling of [`parse_mime_entity`], used ONLY for a nested multipart
/// part's body. Same depth-cap-bail / find-boundary / dispatch logic, but takes the ALREADY
/// EXTRACTED `Content-Type` header value (a small string - just the header, not the whole
/// entity) and the body as a borrowed `&str` slice - no `format!` re-embedding of the body, so
/// this recursion step is zero-allocation for the body itself (`find_boundary` scans the small
/// header value, and `parse_multipart_body`'s own `.split()` below borrows from `body`).
fn parse_nested_multipart(content_type_full: &str, body: &str, depth: usize) -> MimeParsed {
    if depth >= MAX_MIME_DEPTH {
        return parse_single_part(body);
    }
    match find_boundary(content_type_full) {
        Some(boundary) if !boundary.is_empty() => parse_multipart_body(body, &boundary, depth),
        _ => parse_single_part(body),
    }
}

/// Mirrors Dart `_parseMultipartBody`: split on `--<boundary>`, skip the
/// preamble (part 0), stop at the closing `--` epilogue, split each part into
/// headers/body and classify.
fn parse_multipart_body(content: &str, boundary: &str, depth: usize) -> MimeParsed {
    let mut result = MimeParsed::default();
    let delim = format!("--{boundary}");
    let parts: Vec<&str> = content.split(delim.as_str()).collect();
    // parts[0] = preamble (ignored).
    for (part_count, part) in parts.iter().skip(1).enumerate() {
        let mut part: &str = part;
        // The well-formed closing `--boundary--` epilogue always lands in this split as its own
        // segment (checked BEFORE the width cap below): a message with exactly MAX_MIME_PARTS
        // real parts followed by a normal epilogue must not be reported as truncated just
        // because the epilogue segment's index happens to land on the cap.
        if part.starts_with("--") {
            break; // epilogue (closing `--boundary--`)
        }
        // Width cap: stop appending further parts past MAX_MIME_PARTS (defense-in-depth
        // against a hostile message with an enormous flat part count at one nesting level).
        // Record the drop so the top-level `parse()` call returns `Err`, not a silently
        // partial `Ok`.
        if part_count >= MAX_MIME_PARTS {
            result.truncated = true;
            break;
        }
        // Strip the CRLF / LF immediately after the boundary delimiter line.
        if let Some(rest) = part.strip_prefix("\r\n") {
            part = rest;
        } else if let Some(rest) = part.strip_prefix('\n') {
            part = rest;
        }
        // Header/body separator: prefer CRLFCRLF by EXISTENCE (Dart semantics).
        let (sep, sep_len) = match part.find("\r\n\r\n") {
            Some(i) => (i, 4),
            None => match part.find("\n\n") {
                Some(i) => (i, 2),
                None => continue,
            },
        };
        let headers = &part[..sep];
        let body = &part[sep + sep_len..];
        classify_and_merge(headers, body, &mut result, depth);
    }
    result
}

/// Mirrors Dart `_classifyAndMerge`: route each part by Content-Type /
/// Content-Disposition / filename into body / `html_body` / attachments, recursing
/// (depth+1) on nested multipart/*.
fn classify_and_merge(headers: &str, body: &str, result: &mut MimeParsed, depth: usize) {
    let content_type_full =
        mime_header_value(headers, "Content-Type").unwrap_or_else(|| "text/plain".to_string());
    let content_type = content_type_full
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_lowercase();
    let cte = mime_header_value(headers, "Content-Transfer-Encoding")
        .unwrap_or_else(|| "7bit".to_string())
        .trim()
        .to_lowercase();
    let disposition = mime_header_value(headers, "Content-Disposition")
        .unwrap_or_default()
        .to_lowercase();
    let filename = mime_filename(headers);
    let content_id = mime_header_value(headers, "Content-ID")
        .map(|v| v.replace(['<', '>'], "").trim().to_string());

    // Nested multipart: recurse on the ALREADY-BORROWED `body` slice directly - the prior
    // version re-embedded the entire remaining body into a freshly `format!`-allocated String at
    // EVERY nesting level before recursing, so N levels near the input cap could retain N
    // near-full-size temporary strings simultaneously - ~1.25 GiB from a 64 MiB payload nested 20
    // deep. `find_boundary` only needs the small `content_type_full` header VALUE to locate the
    // boundary parameter, not the reconstructed headers+body; `body` itself never gets copied.
    if content_type.starts_with("multipart/") {
        let inner = parse_nested_multipart(&content_type_full, body, depth + 1);
        result.merge_with(inner);
        return;
    }

    // Attachment: explicit Content-Disposition OR a filename present (the
    // filename takes precedence over content-type so a text/plain *attachment*
    // is not appended to the body).
    if disposition.contains("attachment") || filename.is_some() {
        if let Some(bytes) = decode_part_bytes(body, &cte) {
            if !bytes.is_empty() {
                result.attachments.push(MimeAttachment {
                    filename: filename.unwrap_or_else(|| "attachment".to_string()),
                    mime_type: content_type,
                    content: bytes,
                    content_id,
                });
            }
        }
        return;
    }

    // Text body parts (no attachment marker, no filename).
    if content_type == "text/plain" {
        if result.body.is_empty() {
            result.body = decode_text_part(body, &cte).trim().to_string();
        }
        return;
    }
    if content_type == "text/html" {
        // preserve html_body; first one wins (`??=`).
        if result.html_body.is_none() {
            result.html_body = Some(decode_text_part(body, &cte));
        }
        return;
    }

    // Other types (application/*, image/*, …) with no explicit attachment
    // marker - treat as an unnamed downloadable attachment.
    if let Some(bytes) = decode_part_bytes(body, &cte) {
        if !bytes.is_empty() {
            result.attachments.push(MimeAttachment {
                filename: filename.unwrap_or_else(|| "attachment.bin".to_string()),
                mime_type: content_type,
                content: bytes,
                content_id,
            });
        }
    }
}

/// Mirrors Dart `_parseSingleMimePart`: split header/body, decode by CTE, route
/// text/html → `html_body` else → body.
fn parse_single_part(content: &str) -> MimeParsed {
    let (sep, sep_len) = match content.find("\r\n\r\n") {
        Some(i) => (i, 4),
        None => match content.find("\n\n") {
            Some(i) => (i, 2),
            None => {
                return MimeParsed {
                    body: content.to_string(),
                    ..Default::default()
                }
            }
        },
    };
    let headers = &content[..sep];
    let body = &content[sep + sep_len..];
    let ct = mime_header_value(headers, "Content-Type")
        .unwrap_or_else(|| "text/plain".to_string())
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_lowercase();
    let cte = mime_header_value(headers, "Content-Transfer-Encoding")
        .unwrap_or_else(|| "7bit".to_string())
        .trim()
        .to_lowercase();
    let decoded = decode_text_part(body, &cte);
    if ct == "text/html" {
        MimeParsed {
            html_body: Some(decoded),
            ..Default::default()
        }
    } else {
        MimeParsed {
            body: decoded.trim().to_string(),
            ..Default::default()
        }
    }
}

// ───────────────────────────── header helpers ──────────────────────────────

/// Mirrors Dart `_mimeHeaderValue`: unfold RFC-5322 continuation lines, then
/// case-insensitively match `^<name>\s*:\s*<value>` (first match wins). Returns
/// the trimmed value, or `None` if the header is absent / has an empty value.
fn mime_header_value(headers: &str, name: &str) -> Option<String> {
    let unfolded = unfold_continuations(headers);
    for raw_line in unfolded.split('\n') {
        let line = raw_line.strip_suffix('\r').unwrap_or(raw_line);
        if line.len() < name.len() {
            continue;
        }
        if !line.as_bytes()[..name.len()].eq_ignore_ascii_case(name.as_bytes()) {
            continue;
        }
        // After the name: `\s*` then ':' (the regex allows whitespace before the colon).
        let after_name = line[name.len()..].trim_start();
        let Some(after_colon) = after_name.strip_prefix(':') else {
            continue;
        };
        // `\s*([^\r\n]+)` - a non-empty value is required (≥1 char after the
        // colon, even if whitespace). Empty ⇒ no match (Dart returns null).
        if after_colon.is_empty() {
            continue;
        }
        return Some(after_colon.trim().to_string());
    }
    None
}

/// Replace `\r?\n[ \t]+` runs with a single space (RFC-5322 unfolding),
/// preserving all other bytes (incl. UTF-8) verbatim. Mirrors Dart
/// `replaceAll(RegExp(r'\r?\n[ \t]+'), ' ')`.
fn unfold_continuations(headers: &str) -> String {
    let b = headers.as_bytes();
    let mut out = String::with_capacity(headers.len());
    let mut copy_from = 0usize;
    let mut i = 0usize;
    while i < b.len() {
        let mut j = i;
        if b[j] == b'\r' {
            j += 1;
        }
        if j < b.len() && b[j] == b'\n' {
            let nl_end = j + 1;
            let mut k = nl_end;
            while k < b.len() && (b[k] == b' ' || b[k] == b'\t') {
                k += 1;
            }
            if k > nl_end {
                // Matched \r?\n[ \t]+ across i..k → emit verbatim prefix + a space.
                out.push_str(&headers[copy_from..i]);
                out.push(' ');
                i = k;
                copy_from = k;
                continue;
            }
        }
        i += 1;
    }
    out.push_str(&headers[copy_from..]);
    out
}

/// Mirrors Dart `_mimeFilename`: `filename`/`filename*` param first, else a
/// word-boundary `name` param. Captures until `"`/`;`/CR/LF; trimmed.
fn mime_filename(headers: &str) -> Option<String> {
    find_quoted_param(headers, "filename", true, false)
        .or_else(|| find_quoted_param(headers, "name", false, true))
}

/// Scan `headers` (case-insensitively) for `<key>[*]=` (star allowed iff
/// `allow_star`), optionally requiring a word boundary before `key` (so `name`
/// does not match inside `filename`). Capture the value until the first of
/// `"`/`;`/CR/LF (≥1 char required), trim, return.
fn find_quoted_param(
    headers: &str,
    key: &str,
    allow_star: bool,
    word_boundary: bool,
) -> Option<String> {
    let b = headers.as_bytes();
    let kb = key.as_bytes();
    let mut i = 0usize;
    while i + kb.len() <= b.len() {
        if !b[i..i + kb.len()].eq_ignore_ascii_case(kb) {
            i += 1;
            continue;
        }
        // Word boundary before the key: preceding byte must be a non-word char.
        if word_boundary && i > 0 {
            let prev = b[i - 1];
            let is_word = prev.is_ascii_alphanumeric() || prev == b'_';
            if is_word {
                i += 1;
                continue;
            }
        }
        let mut p = i + kb.len();
        if allow_star && p < b.len() && b[p] == b'*' {
            p += 1;
        }
        if p >= b.len() || b[p] != b'=' {
            i += 1;
            continue;
        }
        p += 1; // past '='
        if p < b.len() && b[p] == b'"' {
            p += 1; // optional opening quote
        }
        let start = p;
        while p < b.len() {
            let c = b[p];
            if c == b'"' || c == b';' || c == b'\r' || c == b'\n' {
                break;
            }
            p += 1;
        }
        if p > start {
            // start..p are ASCII-delimited byte positions → char boundaries.
            return Some(headers[start..p].trim().to_string());
        }
        i += 1;
    }
    None
}

/// Mirrors Dart `boundary="?([^";\s\r\n]+)"?` (first match). Returns the
/// boundary token (sans surrounding quotes), or `None`.
fn find_boundary(content: &str) -> Option<String> {
    let key = b"boundary=";
    let b = content.as_bytes();
    let mut i = 0usize;
    while i + key.len() <= b.len() {
        if !b[i..i + key.len()].eq_ignore_ascii_case(key) {
            i += 1;
            continue;
        }
        let mut p = i + key.len();
        if p < b.len() && b[p] == b'"' {
            p += 1; // optional opening quote
        }
        let start = p;
        while p < b.len() {
            let c = b[p];
            // stop set: `"` `;` whitespace CR LF  (Dart `[^";\s\r\n]`)
            if c == b'"' || c == b';' || c == b'\r' || c == b'\n' || c.is_ascii_whitespace() {
                break;
            }
            p += 1;
        }
        if p > start {
            return Some(content[start..p].to_string());
        }
        i += 1;
    }
    None
}

// ───────────────────────────── body decoders ───────────────────────────────

/// Mirrors Dart `_decodeTextPart`: quoted-printable / base64 (utf8-lossy) / raw.
fn decode_text_part(body: &str, cte: &str) -> String {
    if cte == "quoted-printable" {
        return decode_quoted_printable(body);
    }
    if cte == "base64" {
        let stripped: String = body.chars().filter(|c| !c.is_whitespace()).collect();
        return base64::engine::general_purpose::STANDARD
            .decode(stripped.as_bytes())
            .map_or_else(
                |_| body.to_string(),
                |bytes| String::from_utf8_lossy(&bytes).into_owned(),
            );
    }
    body.to_string() // 7bit / 8bit / binary
}

/// Mirrors Dart `_decodePartBytes`: base64 / quoted-printable / raw utf8 bytes.
/// `None` on a base64 decode failure (Dart returns null → the caller skips).
fn decode_part_bytes(body: &str, cte: &str) -> Option<Vec<u8>> {
    if cte == "base64" {
        let stripped: String = body.chars().filter(|c| !c.is_whitespace()).collect();
        return base64::engine::general_purpose::STANDARD
            .decode(stripped.as_bytes())
            .ok();
    }
    if cte == "quoted-printable" {
        return Some(decode_quoted_printable(body).into_bytes());
    }
    Some(body.as_bytes().to_vec()) // 7bit / 8bit / binary
}

/// Mirrors Dart `_decodeQuotedPrintable`: drop `=\r?\n` soft breaks, decode
/// `=XX` hex, pass other bytes through, utf8-lossy-decode the result. Operates
/// on bytes - quoted-printable is 7-bit ASCII, so byte-iteration matches Dart's
/// code-unit iteration for the real (ASCII) input.
fn decode_quoted_printable(input: &str) -> String {
    // Remove soft line breaks: `=` followed by CRLF or LF.
    let src = input.as_bytes();
    let mut no_soft: Vec<u8> = Vec::with_capacity(src.len());
    let mut i = 0usize;
    while i < src.len() {
        if src[i] == b'=' {
            if i + 1 < src.len() && src[i + 1] == b'\n' {
                i += 2;
                continue;
            }
            if i + 2 < src.len() && src[i + 1] == b'\r' && src[i + 2] == b'\n' {
                i += 3;
                continue;
            }
        }
        no_soft.push(src[i]);
        i += 1;
    }

    let mut out: Vec<u8> = Vec::with_capacity(no_soft.len());
    let len = no_soft.len();
    let mut i = 0usize;
    while i < len {
        if no_soft[i] == b'=' && i + 2 < len {
            // u8 hex decode (no cast): both nibbles are 0..=15 ⇒ the byte fits u8.
            if let (Some(hi), Some(lo)) = (hex_nibble(no_soft[i + 1]), hex_nibble(no_soft[i + 2])) {
                out.push(hi * 16 + lo);
                i += 3;
                continue;
            }
        }
        out.push(no_soft[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Value of a single ASCII hex digit (0..=15), or `None` if not a hex digit.
/// Matches Dart `int.tryParse(<1 char>, radix: 16)` per nibble.
const fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

// ──────────────────── RFC-3156 envelope builder ───────────────────────

/// Build the RFC 3156 §4 `multipart/encrypted` envelope body around an armored
/// [`encrypted_payload`]. The caller prepends routing headers. A faithful port
/// of the client's own envelope builder - gated by a dedicated conformance
/// checker, not byte-identity (the boundary is random in both implementations).
///
/// 🔴: the `application/octet-stream` ciphertext part is **BARE** - no
/// `name=` on Content-Type, no Content-Disposition. RFC 3156 §4 shows neither,
/// and including them makes some clients render Part 2 as a phantom
/// "encrypted.asc" attachment instead of the transparently-decrypted body.
/// (INV-MAIL-026 / the "PGP/MIME envelope is not an attachment" invariant.)
#[must_use]
pub fn build_pgp_envelope(encrypted_payload: &str) -> String {
    let boundary = format!("haven_pgp_{}", random_hex8());
    let tail = if encrypted_payload.ends_with("\r\n") {
        ""
    } else {
        "\r\n"
    };
    format!(
        "Content-Type: multipart/encrypted;\r\n\
         \x20   protocol=\"application/pgp-encrypted\";\r\n\
         \x20   boundary=\"{boundary}\"\r\n\
         \r\n\
         --{boundary}\r\n\
         Content-Type: application/pgp-encrypted\r\n\
         \r\n\
         Version: 1\r\n\
         \r\n\
         --{boundary}\r\n\
         Content-Type: application/octet-stream\r\n\
         \r\n\
         {encrypted_payload}{tail}\r\n\
         --{boundary}--\r\n"
    )
}

/// 8 lowercase-hex chars (4 random bytes) - the MIME boundary suffix. Matches
/// the client's own boundary-generation shape (a boundary needs uniqueness, not
/// cryptographic strength).
fn random_hex8() -> String {
    // Crypto-pathway: a NON-SECRET value (MIME boundary uniqueness, not key
    // material) - an accepted, documented `rand::random` boundary. The global
    // `disallowed_methods` ban still catches secret-context reaches elsewhere.
    #[allow(clippy::disallowed_methods)]
    let bytes: [u8; 4] = rand::random();
    hex::encode(bytes)
}

// ────────────── RFC-2047 outer-header encoders ─────────────
//
// The UNIFIED single impl for cleartext outer RFC-2822 header values (Subject /
// From / To / Cc) shared by the client (via FRB) AND the backend (via a CLI),
// replacing the client's own prior header-encoding functions AND a Python
// standard-library phrase encoder the backend previously used independently.
// A FAITHFUL byte-for-byte port of the client's encoders - that implementation
// is the behavior spec, pinned by a dedicated encoding-behavior test suite
// (mirrored in `tests`).
//
// WHY: raw non-ASCII in an outer header renders as mojibake (em-dash →
// â–). RFC 2047 §2 encoded-words (B-encoding, UTF-8) are the fix; ASCII passes
// through byte-identical so existing mail is unchanged. WHY fold: a long
// non-ASCII value would otherwise be one 600+ char line (RFC 5322 §2.1.1 78/998).
//
// PURITY NOTE: every value reaching [`fold_header_value`] is already pure ASCII
// (either an ASCII-printable `clean`, or B-encoded words / ASCII addr-specs), so
// `str::len()` (bytes) == the Dart `String.length` (UTF-16 code units) == column
// count - the fold arithmetic is byte-identical to Dart's.

/// True iff every UTF-8 byte of `s` is printable ASCII (`0x20..=0x7e`). Mirrors
/// Dart `_isAsciiPrintable` (`utf8.encode(s).every((b) => b >= 0x20 && b < 0x7f)`).
fn is_ascii_printable(s: &str) -> bool {
    s.bytes().all(|b| (0x20..0x7f).contains(&b))
}

/// Replace each CR and each LF with a single space - the header-injection-safety
/// primitive: a header value that retains a CR/LF could terminate its
/// header and inject another. Mirrors Dart `replaceAll(RegExp(r'[\r\n]'), ' ')` - so
/// `"a\r\nb"` → `"a  b"`. No-op on legitimate values → byte-identical for real mail.
fn replace_crlf_with_space(s: &str) -> String {
    s.chars()
        .map(|c| if c == '\r' || c == '\n' { ' ' } else { c })
        .collect()
}

/// RFC 2047 §2 encoded-word for a WHOLE header value (e.g. Subject). ASCII →
/// returned (folded if long); non-ASCII → space-joined `=?UTF-8?B?…?=` words.
/// Mirrors the client's own header-word encoding function.
#[must_use]
pub fn encode_header_word(value: &str) -> String {
    let clean = replace_crlf_with_space(value);
    if is_ascii_printable(&clean) {
        fold_header_value(&clean)
    } else {
        fold_header_value(&b_encode_words(&clean))
    }
}

/// Encode the display-name PHRASE of each address in a From/To/Cc list; the
/// addr-spec (`<a@b>` / bare `a@b`) is never touched. ASCII names pass through
/// unchanged. Mirrors the client's own address-header encoding function.
#[must_use]
pub fn encode_address_header(value: &str) -> String {
    // header-injection safety: strip CR/LF BEFORE assembly. The bare-
    // address and ASCII-display-name branches of `encode_one_address` return their
    // input verbatim, so a CR/LF reaching them would inject a header. Legitimate
    // addresses never contain CR/LF → no-op → byte-identical for real mail.
    let value = replace_crlf_with_space(value);
    let encoded: Vec<String> = split_address_list(&value)
        .iter()
        .map(|p| encode_one_address(p))
        .collect();
    fold_header_value(&encoded.join(", "))
}

/// Fold a header VALUE (RFC 5322 §2.2.3 / RFC 2047 §2 76-char): break at existing
/// spaces so no produced line exceeds `LIMIT` octets; continuation lines begin
/// with a single space. Caller guarantees pure-ASCII input (see module note).
/// Mirrors Dart `_foldHeaderValue` (limit 76).
fn fold_header_value(value: &str) -> String {
    const LIMIT: usize = 76;
    if value.len() <= LIMIT {
        return value.to_string();
    }
    let mut out = String::with_capacity(value.len() + 16);
    let mut line_len = 0usize;
    for (i, t) in value.split(' ').enumerate() {
        if i == 0 {
            out.push_str(t);
            line_len = t.len();
        } else if line_len + 1 + t.len() > LIMIT {
            out.push_str("\r\n ");
            out.push_str(t);
            line_len = 1 + t.len();
        } else {
            out.push(' ');
            out.push_str(t);
            line_len += 1 + t.len();
        }
    }
    out
}

/// B-encode `s` as one or more space-separated RFC-2047 encoded-words. Each word
/// is ≤75 chars: overhead `=?UTF-8?B?` + `?=` = 12, so ≤63 b64 chars → ≤45 source
/// bytes, grouped on whole UTF-8 characters so no word splits a multibyte char.
/// Mirrors Dart `_bEncodeWords`.
fn b_encode_words(s: &str) -> String {
    const MAX_BYTES_PER_WORD: usize = 45;
    let mut words: Vec<String> = Vec::new();
    let mut chunk: Vec<u8> = Vec::new();
    let mut buf = [0u8; 4];
    for ch in s.chars() {
        let rune_bytes = ch.encode_utf8(&mut buf).as_bytes();
        if chunk.len() + rune_bytes.len() > MAX_BYTES_PER_WORD && !chunk.is_empty() {
            words.push(format!(
                "=?UTF-8?B?{}?=",
                base64::engine::general_purpose::STANDARD.encode(&chunk)
            ));
            chunk.clear();
        }
        chunk.extend_from_slice(rune_bytes);
    }
    if !chunk.is_empty() {
        words.push(format!(
            "=?UTF-8?B?{}?=",
            base64::engine::general_purpose::STANDARD.encode(&chunk)
        ));
    }
    words.join(" ")
}

/// Quote-aware split of an address list on top-level commas (a comma inside a
/// quoted display-name is NOT a separator). Parts are NOT trimmed (the caller
/// trims). Mirrors Dart `_splitAddressList`.
fn split_address_list(value: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut buf = String::new();
    let mut in_quotes = false;
    for c in value.chars() {
        if c == '"' {
            in_quotes = !in_quotes;
        }
        if c == ',' && !in_quotes {
            out.push(std::mem::take(&mut buf));
        } else {
            buf.push(c);
        }
    }
    if !buf.is_empty() {
        out.push(buf);
    }
    out
}

/// Encode one address: phrase B-encoded iff non-ASCII, the addr-spec untouched.
/// `"José" <j@x>` → `=?UTF-8?B?…?= <j@x>`. Mirrors Dart `_encodeOneAddress`
/// (`lastIndexOf('<') <= 0` → return as-is; quotes stripped before encoding).
fn encode_one_address(addr: &str) -> String {
    let a = addr.trim();
    match a.rfind('<') {
        None | Some(0) => a.to_string(),
        Some(lt) => {
            let phrase = a[..lt].trim();
            let spec = &a[lt..]; // "<addr>"
            if phrase.is_empty() || is_ascii_printable(phrase) {
                return a.to_string();
            }
            // Strip one layer of surrounding quotes before encoding the phrase
            // (the quotes are ASCII, so byte-slicing matches Dart's code-unit substring).
            let phrase = if phrase.len() >= 2 && phrase.starts_with('"') && phrase.ends_with('"') {
                &phrase[1..phrase.len() - 1]
            } else {
                phrase
            };
            format!("{} {spec}", b_encode_words(phrase))
        }
    }
}

// ──────────── Full outer assembly + inner wrap (unified builder) ────────────

/// Assemble the complete RFC-2822 message: canonical outer routing headers
/// (RFC-2047 encoded) + the supplied `pgp_mime_body` (which begins with its own
/// `Content-Type: multipart/encrypted…\r\n\r\n<parts>`). The UNIFIED outer builder -
/// a faithful port of the client's own outer-assembly function, now shared
/// by the client (FRB) and the backend (a CLI), so the wire format is single-source.
///
/// Header order (the canonical format): `MIME-Version`, `From`, `To`, [`Cc`],
/// `Subject`, `Date`, `Message-ID`, [`In-Reply-To`], [`References`], [extra…], then
/// the body. `date` + `message_id` are PRE-FORMATTED by the caller (their generation
/// is platform-specific and NOT the unification target; only the assembly + RFC-2047
/// encoding is unified). From/To/Cc go through [`encode_address_header`] (phrase-only
/// encoding); Subject + every extra value go through [`encode_header_word`]
/// (whole-value, CR/LF-stripped → injection-safe).
#[must_use]
pub fn build_full_outer_mime(
    pgp_mime_body: &str,
    routing: &OuterRouting,
    extra_headers: &[(String, String)],
) -> String {
    let mut buf = String::with_capacity(pgp_mime_body.len() + 512);
    buf.push_str("MIME-Version: 1.0\r\n");
    buf.push_str("From: ");
    buf.push_str(&encode_address_header(&routing.from));
    buf.push_str("\r\n");
    buf.push_str("To: ");
    buf.push_str(&encode_address_header(&routing.to));
    buf.push_str("\r\n");
    if let Some(cc) = routing.cc.as_deref().filter(|c| !c.is_empty()) {
        buf.push_str("Cc: ");
        buf.push_str(&encode_address_header(cc));
        buf.push_str("\r\n");
    }
    buf.push_str("Subject: ");
    buf.push_str(&encode_header_word(&routing.subject));
    buf.push_str("\r\n");
    // Date/Message-ID/In-Reply-To/References are NOT RFC-2047-encoded
    // (they're structured tokens), so they need explicit CR/LF stripping - In-Reply-To
    // / References especially, since they derive from a received message's Message-ID
    // (attacker-influenced). Extra-header VALUES go through encode_header_word (which
    // already strips); extra KEYS are stripped defensively.
    buf.push_str("Date: ");
    buf.push_str(&replace_crlf_with_space(&routing.date));
    buf.push_str("\r\n");
    buf.push_str("Message-ID: ");
    buf.push_str(&replace_crlf_with_space(&routing.message_id));
    buf.push_str("\r\n");
    if let Some(v) = routing.in_reply_to.as_deref().filter(|c| !c.is_empty()) {
        buf.push_str("In-Reply-To: ");
        buf.push_str(&replace_crlf_with_space(v));
        buf.push_str("\r\n");
    }
    if let Some(v) = routing.references.as_deref().filter(|c| !c.is_empty()) {
        buf.push_str("References: ");
        buf.push_str(&replace_crlf_with_space(v));
        buf.push_str("\r\n");
    }
    for (k, v) in extra_headers {
        buf.push_str(&replace_crlf_with_space(k));
        buf.push_str(": ");
        buf.push_str(&encode_header_word(v));
        buf.push_str("\r\n");
    }
    buf.push_str(pgp_mime_body);
    buf
}

/// Routing headers for [`build_full_outer_mime`]. `date` + `message_id` are
/// pre-formatted strings (caller-generated); `from`/`to`/`subject` are raw (the
/// builder RFC-2047-encodes them). Mirrors the param set of the client's own
/// outer-assembly function.
#[derive(Clone, Debug, Default)]
pub struct OuterRouting {
    pub from: String,
    pub to: String,
    pub subject: String,
    pub date: String,
    pub message_id: String,
    pub cc: Option<String>,
    pub in_reply_to: Option<String>,
    pub references: Option<String>,
}

/// Wrap branded HTML as a single-part RFC-2387 `multipart/related; type="text/html"`
/// block - the welcome-series inner (HTML-only, no attachments). Replaces the backend
/// Python `build_inner_related_html`'s `email.mime` wrap. A leading `MIME-Version: 1.0`
/// is prepended so Haven's client decrypt parser recognises the inner payload (it keys
/// on a leading `MIME-Version:` / a `Content-Type: multipart/`). The `text/html` part
/// is `8bit` (UTF-8 HTML; the OUTER is PGP-armored ASCII on the wire). RFC 2387 §3.1:
/// the `type=` param is REQUIRED and names the root part's media type (verified by a
/// dedicated conformance check).
#[must_use]
pub fn build_related_html(html: &str) -> String {
    let boundary = format!("haven_rel_{}", random_hex8());
    let tail = if html.ends_with("\r\n") { "" } else { "\r\n" };
    let mut buf = String::with_capacity(html.len() + 256);
    buf.push_str("MIME-Version: 1.0\r\n");
    buf.push_str("Content-Type: multipart/related;\r\n");
    buf.push_str("    type=\"text/html\";\r\n");
    buf.push_str("    boundary=\"");
    buf.push_str(&boundary);
    buf.push_str("\"\r\n\r\n--");
    buf.push_str(&boundary);
    buf.push_str("\r\n");
    buf.push_str("Content-Type: text/html; charset=utf-8\r\n");
    buf.push_str("Content-Transfer-Encoding: 8bit\r\n\r\n");
    buf.push_str(html);
    buf.push_str(tail);
    buf.push_str("--");
    buf.push_str(&boundary);
    buf.push_str("--\r\n");
    buf
}

#[cfg(test)]
mod tests;
