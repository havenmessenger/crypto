//! A compact binary form for the values openmls stores.
//!
//! openmls writes each storage value as compact `serde_json` text, and byte strings in that text are
//! arrays of decimal numbers, so every byte of a key or a tree costs three or four bytes. This module
//! rewrites such a value as a binary tree of the same JSON and back, and the round trip is exact: the
//! text that comes out is byte-for-byte the text that went in, so a consumer's idea of whether an entry
//! changed does not depend on which form it holds. A byte string becomes raw bytes, a small integer one
//! varint, and a number it cannot make smaller is copied as it was. A string or an object key that
//! occurs again in the same value (a tree repeats the same field names for every leaf) is written once
//! and then referred to by its place in a table.
//!
//! A stored value starts with a form byte: [`FORM_BINARY`] for the tree, [`FORM_RAW`] for text kept as
//! it was (anything that is not compact JSON, and anything too deeply nested to rewrite safely). A value
//! with neither, such as a JSON value an older version wrote, is read as raw text.

use zeroize::Zeroizing;

use crate::mls::store::MlsStoreError;

/// The form byte of a value rewritten as a binary tree.
pub const FORM_BINARY: u8 = 0xB1;
/// The form byte of a value kept as text.
pub const FORM_RAW: u8 = 0x00;

const NULL: u8 = 0;
const TRUE: u8 = 1;
const FALSE: u8 = 2;
const UINT: u8 = 3;
const NEG: u8 = 4;
const NUMBER_TEXT: u8 = 5;
const STRING: u8 = 6;
const ARRAY: u8 = 7;
const OBJECT: u8 = 8;
const BYTES: u8 = 9;

/// Strings shorter than this are always written out; a reference would not be smaller.
const MIN_TABLED: usize = 3;

/// Nesting deeper than this is kept as text: decoding recurses once per level.
const MAX_DEPTH: usize = 64;

/// `json` in its stored form.
#[must_use]
pub fn encode_value(json: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(json.len() / 2 + 2);
    out.push(FORM_BINARY);
    let mut parser = Parser {
        text: json,
        at: 0,
        seen: std::collections::HashMap::new(),
    };
    if parser.value(&mut out, 0).is_some() && parser.at == json.len() {
        return out;
    }
    let mut raw = Vec::with_capacity(json.len() + 1);
    raw.push(FORM_RAW);
    raw.extend_from_slice(json);
    raw
}

/// The text a stored value stands for.
pub fn decode_value(stored: &[u8]) -> Result<Zeroizing<Vec<u8>>, MlsStoreError> {
    match stored.first() {
        Some(&FORM_BINARY) => {
            let mut out = Zeroizing::new(Vec::with_capacity(stored.len() * 3));
            let mut reader = Reader {
                bytes: &stored[1..],
                at: 0,
                table: Vec::new(),
            };
            reader.value(&mut out, 0)?;
            if reader.at != reader.bytes.len() {
                return Err(corrupt("trailing bytes after a value"));
            }
            Ok(out)
        }
        Some(&FORM_RAW) => Ok(Zeroizing::new(stored[1..].to_vec())),
        _ => Ok(Zeroizing::new(stored.to_vec())),
    }
}

/// Append the decimal digits of `value` without allocating.
fn push_decimal(out: &mut Vec<u8>, mut value: u64) {
    let mut digits = [0u8; 20];
    let mut at = digits.len();
    loop {
        at -= 1;
        digits[at] = b'0' + (value % 10) as u8;
        value /= 10;
        if value == 0 {
            break;
        }
    }
    out.extend_from_slice(&digits[at..]);
}

fn corrupt(what: &str) -> MlsStoreError {
    MlsStoreError::Corrupt(format!("stored value: {what}"))
}

#[allow(clippy::cast_possible_truncation)] // each byte is masked to seven bits (the last is below 0x80)
fn put_varint(out: &mut Vec<u8>, mut value: u64) {
    while value >= 0x80 {
        out.push((value & 0x7f) as u8 | 0x80);
        value >>= 7;
    }
    out.push(value as u8);
}

/// Reads compact JSON text and writes its binary tree, giving up (`None`) on anything it would not
/// reproduce exactly.
struct Parser<'a> {
    text: &'a [u8],
    at: usize,
    seen: std::collections::HashMap<&'a [u8], u64>,
}

impl<'a> Parser<'a> {
    fn peek(&self) -> Option<u8> {
        self.text.get(self.at).copied()
    }

    fn literal(&mut self, word: &[u8]) -> Option<()> {
        if self.text[self.at..].starts_with(word) {
            self.at += word.len();
            Some(())
        } else {
            None
        }
    }

    fn value(&mut self, out: &mut Vec<u8>, depth: usize) -> Option<()> {
        if depth > MAX_DEPTH {
            return None;
        }
        match self.peek()? {
            b'n' => {
                self.literal(b"null")?;
                out.push(NULL);
            }
            b't' => {
                self.literal(b"true")?;
                out.push(TRUE);
            }
            b'f' => {
                self.literal(b"false")?;
                out.push(FALSE);
            }
            b'"' => {
                let body = self.string_body()?;
                out.push(STRING);
                self.token(body, out);
            }
            b'[' => self.array(out, depth)?,
            b'{' => self.object(out, depth)?,
            b'-' | b'0'..=b'9' => self.number(out),
            _ => return None,
        }
        Some(())
    }

    /// The text between the quotes of a string, escapes untouched.
    fn string_body(&mut self) -> Option<&'a [u8]> {
        debug_assert_eq!(self.peek(), Some(b'"'));
        let text: &'a [u8] = self.text;
        let start = self.at + 1;
        let mut at = start;
        loop {
            match *text.get(at)? {
                b'"' => {
                    self.at = at + 1;
                    return Some(&text[start..at]);
                }
                b'\\' => at += 2,
                _ => at += 1,
            }
        }
    }

    /// Write a string: its text the first time, then a reference to the table once it has been seen.
    fn token(&mut self, body: &'a [u8], out: &mut Vec<u8>) {
        if body.len() >= MIN_TABLED {
            if let Some(&index) = self.seen.get(body) {
                put_varint(out, (index << 1) | 1);
                return;
            }
            let index = self.seen.len() as u64;
            self.seen.insert(body, index);
        }
        put_varint(out, (body.len() as u64) << 1);
        out.extend_from_slice(body);
    }

    fn number(&mut self, out: &mut Vec<u8>) {
        let start = self.at;
        while matches!(
            self.peek(),
            Some(b'-' | b'+' | b'.' | b'e' | b'E' | b'0'..=b'9')
        ) {
            self.at += 1;
        }
        let text = &self.text[start..self.at];
        match canonical_uint(text) {
            Some(value) => {
                out.push(UINT);
                put_varint(out, value);
            }
            None => match text.strip_prefix(b"-").and_then(canonical_uint) {
                Some(value) if value > 0 => {
                    out.push(NEG);
                    put_varint(out, value);
                }
                _ => {
                    out.push(NUMBER_TEXT);
                    put_varint(out, text.len() as u64);
                    out.extend_from_slice(text);
                }
            },
        }
    }

    fn array(&mut self, out: &mut Vec<u8>, depth: usize) -> Option<()> {
        self.at += 1;
        if self.peek()? == b']' {
            self.at += 1;
            out.push(ARRAY);
            put_varint(out, 0);
            return Some(());
        }
        let start = out.len();
        let mut count = 0u64;
        let mut small = true;
        let mut elements = Vec::new();
        loop {
            let from = elements.len();
            self.value(&mut elements, depth + 1)?;
            count += 1;
            let element = &elements[from..];
            small &= element.len() == 2 && element[0] == UINT && element[1] < 0x80
                || element.len() == 3
                    && element[0] == UINT
                    && element[1] >= 0x80
                    && element[2] == 1;
            match self.peek()? {
                b',' => self.at += 1,
                b']' => {
                    self.at += 1;
                    break;
                }
                _ => return None,
            }
        }
        debug_assert_eq!(out.len(), start);
        if small {
            out.push(BYTES);
            put_varint(out, count);
            let mut at = 0;
            while at < elements.len() {
                // each element is UINT then a varint of at most 255
                let first = elements[at + 1];
                if first < 0x80 {
                    out.push(first);
                    at += 2;
                } else {
                    out.push((first & 0x7f) | (elements[at + 2] << 7));
                    at += 3;
                }
            }
        } else {
            out.push(ARRAY);
            put_varint(out, count);
            out.extend_from_slice(&elements);
        }
        Some(())
    }

    fn object(&mut self, out: &mut Vec<u8>, depth: usize) -> Option<()> {
        self.at += 1;
        out.push(OBJECT);
        if self.peek()? == b'}' {
            self.at += 1;
            put_varint(out, 0);
            return Some(());
        }
        let mut members = Vec::new();
        let mut count = 0u64;
        loop {
            if self.peek()? != b'"' {
                return None;
            }
            let key = self.string_body()?;
            self.token(key, &mut members);
            if self.peek()? != b':' {
                return None;
            }
            self.at += 1;
            self.value(&mut members, depth + 1)?;
            count += 1;
            match self.peek()? {
                b',' => self.at += 1,
                b'}' => {
                    self.at += 1;
                    break;
                }
                _ => return None,
            }
        }
        put_varint(out, count);
        out.extend_from_slice(&members);
        Some(())
    }
}

/// The value of a decimal integer written the way `serde_json` writes one: no sign, no leading zero.
fn canonical_uint(text: &[u8]) -> Option<u64> {
    let digits_ok = !text.is_empty()
        && text.iter().all(u8::is_ascii_digit)
        && (text.len() == 1 || text[0] != b'0');
    if !digits_ok {
        return None;
    }
    std::str::from_utf8(text).ok()?.parse().ok()
}

/// Writes the JSON text a binary tree stands for.
struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
    table: Vec<std::ops::Range<usize>>,
}

impl Reader<'_> {
    fn byte(&mut self) -> Result<u8, MlsStoreError> {
        let byte = *self
            .bytes
            .get(self.at)
            .ok_or_else(|| corrupt("ends early"))?;
        self.at += 1;
        Ok(byte)
    }

    fn varint(&mut self) -> Result<u64, MlsStoreError> {
        let mut value = 0u64;
        for shift in (0..64).step_by(7) {
            let byte = self.byte()?;
            value |= u64::from(byte & 0x7f) << shift;
            if byte & 0x80 == 0 {
                return Ok(value);
            }
        }
        Err(corrupt("a length is too long"))
    }

    fn take(&mut self, len: u64) -> Result<&[u8], MlsStoreError> {
        let len = usize::try_from(len).map_err(|_| corrupt("a length is too large"))?;
        let end = self
            .at
            .checked_add(len)
            .ok_or_else(|| corrupt("a length is too large"))?;
        let slice = self
            .bytes
            .get(self.at..end)
            .ok_or_else(|| corrupt("ends early"))?;
        self.at = end;
        Ok(slice)
    }

    /// Read a string, from the table or written out, and append its text to `out` between quotes.
    fn token(&mut self, out: &mut Vec<u8>) -> Result<(), MlsStoreError> {
        let head = self.varint()?;
        let bytes: &[u8] = self.bytes;
        if head & 1 == 1 {
            let range = usize::try_from(head >> 1)
                .ok()
                .and_then(|index| self.table.get(index))
                .ok_or_else(|| corrupt("a reference to a string not seen"))?
                .clone();
            out.extend_from_slice(&bytes[range]);
        } else {
            let len = head >> 1;
            let start = self.at;
            let text = self.take(len)?;
            let width = text.len();
            out.extend_from_slice(text);
            if width >= MIN_TABLED {
                self.table.push(start..start + width);
            }
        }
        Ok(())
    }

    fn value(&mut self, out: &mut Vec<u8>, depth: usize) -> Result<(), MlsStoreError> {
        if depth > MAX_DEPTH {
            return Err(corrupt("nested too deeply"));
        }
        match self.byte()? {
            NULL => out.extend_from_slice(b"null"),
            TRUE => out.extend_from_slice(b"true"),
            FALSE => out.extend_from_slice(b"false"),
            UINT => push_decimal(out, self.varint()?),
            NEG => {
                out.push(b'-');
                push_decimal(out, self.varint()?);
            }
            NUMBER_TEXT => {
                let len = self.varint()?;
                out.extend_from_slice(self.take(len)?);
            }
            STRING => {
                out.push(b'"');
                self.token(out)?;
                out.push(b'"');
            }
            BYTES => {
                let count = self.varint()?;
                let bytes = self.take(count)?;
                out.push(b'[');
                for (index, byte) in bytes.iter().enumerate() {
                    if index > 0 {
                        out.push(b',');
                    }
                    push_decimal(out, u64::from(*byte));
                }
                out.push(b']');
            }
            ARRAY => {
                let count = self.varint()?;
                out.push(b'[');
                for index in 0..count {
                    if index > 0 {
                        out.push(b',');
                    }
                    self.value(out, depth + 1)?;
                }
                out.push(b']');
            }
            OBJECT => {
                let count = self.varint()?;
                out.push(b'{');
                for index in 0..count {
                    if index > 0 {
                        out.push(b',');
                    }
                    out.push(b'"');
                    self.token(out)?;
                    out.extend_from_slice(b"\":");
                    self.value(out, depth + 1)?;
                }
                out.push(b'}');
            }
            _ => return Err(corrupt("an unknown tag")),
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
