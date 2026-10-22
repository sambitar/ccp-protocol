//! Strict canonical JSON per CCP §25.1.

use std::collections::HashSet;

use num_bigint::BigUint;
use unicode_normalization::UnicodeNormalization;

use crate::value::Value;

const SHORT_ESCAPES: [(char, &str); 5] = [
    ('\u{8}', "\\b"),
    ('\u{c}', "\\f"),
    ('\n', "\\n"),
    ('\r', "\\r"),
    ('\t', "\\t"),
];

/// Encode one string using the minimal escape set, NFC-normalized.
pub fn quote(text: &str) -> String {
    let normalized: String = text.nfc().collect();
    let mut out = String::with_capacity(normalized.len() + 2);
    out.push('"');
    for ch in normalized.chars() {
        if ch == '"' {
            out.push_str("\\\"");
        } else if ch == '\\' {
            out.push_str("\\\\");
        } else if let Some(escape) = SHORT_ESCAPES
            .iter()
            .find(|(candidate, _)| *candidate == ch)
            .map(|(_, escape)| *escape)
        {
            out.push_str(escape);
        } else if (ch as u32) < 0x20 {
            out.push_str(&format!("\\u{:04x}", ch as u32));
        } else {
            out.push(ch);
        }
    }
    out.push('"');
    out
}

/// Serialize a value canonically. `signature` is emitted last only in the
/// top-level object.
pub fn serialize(value: &Value) -> Result<String, String> {
    serialize_at(value, true)
}

fn serialize_at(value: &Value, top_level: bool) -> Result<String, String> {
    match value {
        Value::Null => Ok("null".to_string()),
        Value::Bool(true) => Ok("true".to_string()),
        Value::Bool(false) => Ok("false".to_string()),
        Value::Int(number) => Ok(number.to_string()),
        Value::Str(text) => Ok(quote(text)),
        Value::Array(items) => {
            let mut parts = Vec::with_capacity(items.len());
            for item in items {
                parts.push(serialize_at(item, false)?);
            }
            Ok(format!("[{}]", parts.join(",")))
        }
        Value::Object(entries) => {
            let mut folded: Vec<(String, &Value)> = Vec::with_capacity(entries.len());
            let mut seen: HashSet<String> = HashSet::new();
            for (key, item) in entries {
                if top_level && key == "signature" {
                    continue;
                }
                let normalized: String = key.nfc().collect();
                if !seen.insert(normalized.clone()) {
                    return Err("duplicate".to_string());
                }
                folded.push((normalized, item));
            }
            folded.sort_by(|left, right| left.0.cmp(&right.0));

            let mut parts = Vec::with_capacity(folded.len() + 1);
            for (key, item) in folded {
                parts.push(format!("{}:{}", quote(&key), serialize_at(item, false)?));
            }
            if top_level {
                if let Some((_, signature)) = entries.iter().find(|(key, _)| key == "signature") {
                    parts.push(format!("\"signature\":{}", serialize_at(signature, false)?));
                }
            }
            Ok(format!("{{{}}}", parts.join(",")))
        }
    }
}

/// Parse a JSON document with the profile's strictness.
pub fn parse_strict(text: &str) -> Result<Value, String> {
    let mut parser = Parser { text, pos: 0 };
    parser.skip_whitespace();
    let value = parser.parse_value()?;
    parser.skip_whitespace();
    if parser.pos != text.len() {
        return Err("malformed".to_string());
    }
    Ok(value)
}

struct Parser<'a> {
    text: &'a str,
    pos: usize,
}

impl<'a> Parser<'a> {
    fn peek(&self) -> Option<char> {
        self.text[self.pos..].chars().next()
    }

    fn bump(&mut self) -> Option<char> {
        let ch = self.peek()?;
        self.pos += ch.len_utf8();
        Some(ch)
    }

    fn skip_whitespace(&mut self) {
        while let Some(ch) = self.peek() {
            if ch == ' ' || ch == '\t' || ch == '\n' || ch == '\r' {
                self.pos += 1;
            } else {
                break;
            }
        }
    }

    fn expect(&mut self, expected: char) -> Result<(), String> {
        if self.peek() == Some(expected) {
            self.pos += expected.len_utf8();
            Ok(())
        } else {
            Err("malformed".to_string())
        }
    }

    fn expect_word(&mut self, word: &str) -> Result<(), String> {
        if self.text[self.pos..].starts_with(word) {
            self.pos += word.len();
            Ok(())
        } else {
            Err("malformed".to_string())
        }
    }

    fn parse_value(&mut self) -> Result<Value, String> {
        self.skip_whitespace();
        match self.peek() {
            Some('{') => self.parse_object(),
            Some('[') => self.parse_array(),
            Some('"') => self.parse_string().map(Value::Str),
            Some('t') => {
                self.expect_word("true")?;
                Ok(Value::Bool(true))
            }
            Some('f') => {
                self.expect_word("false")?;
                Ok(Value::Bool(false))
            }
            Some('n') => {
                self.expect_word("null")?;
                Ok(Value::Null)
            }
            Some('N') | Some('I') => Err("constant".to_string()),
            Some('-') => {
                if self.text[self.pos..].starts_with("-Infinity") {
                    Err("constant".to_string())
                } else {
                    Err("negative".to_string())
                }
            }
            Some(ch) if ch.is_ascii_digit() => self.parse_number(),
            _ => Err("malformed".to_string()),
        }
    }

    fn parse_string(&mut self) -> Result<String, String> {
        self.expect('"')?;
        let mut out = String::new();
        loop {
            let ch = self.bump().ok_or_else(|| "malformed".to_string())?;
            match ch {
                '"' => return Ok(out),
                '\\' => {
                    let escape = self.bump().ok_or_else(|| "malformed".to_string())?;
                    match escape {
                        '"' => out.push('"'),
                        '\\' => out.push('\\'),
                        '/' => out.push('/'),
                        'b' => out.push('\u{8}'),
                        'f' => out.push('\u{c}'),
                        'n' => out.push('\n'),
                        'r' => out.push('\r'),
                        't' => out.push('\t'),
                        'u' => {
                            let code = self.parse_hex4()?;
                            if (0xD800..=0xDBFF).contains(&code) {
                                if self.bump() != Some('\\') || self.bump() != Some('u') {
                                    return Err("malformed".to_string());
                                }
                                let low = self.parse_hex4()?;
                                if !(0xDC00..=0xDFFF).contains(&low) {
                                    return Err("malformed".to_string());
                                }
                                let scalar = 0x10000 + ((code - 0xD800) << 10) + (low - 0xDC00);
                                out.push(
                                    char::from_u32(scalar)
                                        .ok_or_else(|| "malformed".to_string())?,
                                );
                            } else if (0xDC00..=0xDFFF).contains(&code) {
                                return Err("malformed".to_string());
                            } else {
                                out.push(
                                    char::from_u32(code).ok_or_else(|| "malformed".to_string())?,
                                );
                            }
                        }
                        _ => return Err("malformed".to_string()),
                    }
                }
                ch if (ch as u32) < 0x20 => return Err("malformed".to_string()),
                ch => out.push(ch),
            }
        }
    }

    fn parse_hex4(&mut self) -> Result<u32, String> {
        let mut code = 0u32;
        for _ in 0..4 {
            let ch = self.bump().ok_or_else(|| "malformed".to_string())?;
            let digit = ch.to_digit(16).ok_or_else(|| "malformed".to_string())?;
            code = code * 16 + digit;
        }
        Ok(code)
    }

    fn parse_number(&mut self) -> Result<Value, String> {
        let start = self.pos;
        while let Some(ch) = self.peek() {
            if ch.is_ascii_digit() {
                self.pos += 1;
            } else {
                break;
            }
        }
        match self.peek() {
            Some('.') | Some('e') | Some('E') => return Err("float".to_string()),
            _ => {}
        }
        let digits = &self.text[start..self.pos];
        if digits.len() > 1 && digits.starts_with('0') {
            return Err("malformed".to_string());
        }
        let number =
            BigUint::parse_bytes(digits.as_bytes(), 10).ok_or_else(|| "malformed".to_string())?;
        Ok(Value::Int(number))
    }

    fn parse_array(&mut self) -> Result<Value, String> {
        self.expect('[')?;
        let mut items = Vec::new();
        self.skip_whitespace();
        if self.peek() == Some(']') {
            self.bump();
            return Ok(Value::Array(items));
        }
        loop {
            items.push(self.parse_value()?);
            self.skip_whitespace();
            match self.peek() {
                Some(',') => {
                    self.bump();
                }
                Some(']') => {
                    self.bump();
                    return Ok(Value::Array(items));
                }
                _ => return Err("malformed".to_string()),
            }
        }
    }

    fn parse_object(&mut self) -> Result<Value, String> {
        self.expect('{')?;
        let mut entries: Vec<(String, Value)> = Vec::new();
        let mut seen: HashSet<String> = HashSet::new();
        self.skip_whitespace();
        if self.peek() == Some('}') {
            self.bump();
            return Ok(Value::Object(entries));
        }
        loop {
            self.skip_whitespace();
            if self.peek() != Some('"') {
                return Err("malformed".to_string());
            }
            let key = self.parse_string()?;
            let folded: String = key.nfc().collect();
            if !seen.insert(folded) {
                return Err("duplicate".to_string());
            }
            self.skip_whitespace();
            self.expect(':')?;
            let value = self.parse_value()?;
            entries.push((key, value));
            self.skip_whitespace();
            match self.peek() {
                Some(',') => {
                    self.bump();
                }
                Some('}') => {
                    self.bump();
                    return Ok(Value::Object(entries));
                }
                _ => return Err("malformed".to_string()),
            }
        }
    }
}
