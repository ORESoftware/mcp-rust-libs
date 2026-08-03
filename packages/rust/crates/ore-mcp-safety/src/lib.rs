//! Bounded-output, redaction, and identifier-safety primitives.

#![forbid(unsafe_code)]

use std::borrow::Cow;

/// Default upper bounds shared by diagnostic MCP tools.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Bounds {
    /// Maximum UTF-8 text payload size.
    pub max_text_bytes: usize,
    /// Maximum serialized JSON payload size.
    pub max_json_bytes: usize,
}

impl Bounds {
    /// Conservative fleet defaults: 256 KiB text and 1 MiB JSON.
    pub const DEFAULT: Self = Self {
        max_text_bytes: 256 * 1024,
        max_json_bytes: 1024 * 1024,
    };

    /// Constructs validated bounds.
    ///
    /// # Errors
    ///
    /// Returns an error when either value is outside the supported 1 KiB to
    /// 16 MiB range.
    pub fn new(max_text_bytes: usize, max_json_bytes: usize) -> Result<Self, BoundError> {
        const MIN: usize = 1024;
        const MAX: usize = 16 * 1024 * 1024;
        if !(MIN..=MAX).contains(&max_text_bytes) {
            return Err(BoundError::TextOutOfRange);
        }
        if !(MIN..=MAX).contains(&max_json_bytes) {
            return Err(BoundError::JsonOutOfRange);
        }
        Ok(Self {
            max_text_bytes,
            max_json_bytes,
        })
    }
}

impl Default for Bounds {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// Validation failures for [`Bounds`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BoundError {
    /// The text bound is outside the supported range.
    TextOutOfRange,
    /// The JSON bound is outside the supported range.
    JsonOutOfRange,
}

/// Truncates a string at a UTF-8 boundary and appends `suffix`.
///
/// The returned value never exceeds `max_bytes`. When the suffix itself does
/// not fit, an empty borrowed string is returned.
#[must_use]
pub fn truncate_utf8<'a>(value: &'a str, max_bytes: usize, suffix: &str) -> Cow<'a, str> {
    if value.len() <= max_bytes {
        return Cow::Borrowed(value);
    }
    if suffix.len() > max_bytes {
        return Cow::Borrowed("");
    }
    let mut end = max_bytes - suffix.len();
    while end > 0 && !value.is_char_boundary(end) {
        end -= 1;
    }
    let mut output = String::with_capacity(end + suffix.len());
    output.push_str(&value[..end]);
    output.push_str(suffix);
    Cow::Owned(output)
}

/// Incremental byte buffer that rejects the first byte beyond a fixed limit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BoundedBytes {
    limit: usize,
    bytes: Vec<u8>,
}

impl BoundedBytes {
    /// Constructs an empty bounded buffer.
    ///
    /// # Errors
    ///
    /// Rejects limits outside 1 KiB through 16 MiB.
    pub fn new(limit: usize) -> Result<Self, BoundError> {
        if !(1024..=16 * 1024 * 1024).contains(&limit) {
            return Err(BoundError::JsonOutOfRange);
        }
        Ok(Self {
            limit,
            bytes: Vec::new(),
        })
    }

    /// Appends one chunk without ever retaining an over-limit prefix.
    ///
    /// # Errors
    ///
    /// Returns [`BoundError::JsonOutOfRange`] when the chunk would exceed the
    /// configured limit or when length arithmetic overflows.
    pub fn extend_from_slice(&mut self, chunk: &[u8]) -> Result<(), BoundError> {
        let next = self
            .bytes
            .len()
            .checked_add(chunk.len())
            .ok_or(BoundError::JsonOutOfRange)?;
        if next > self.limit {
            return Err(BoundError::JsonOutOfRange);
        }
        self.bytes.extend_from_slice(chunk);
        Ok(())
    }

    /// Returns the current number of retained bytes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Returns whether no bytes have been retained.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// Consumes the accumulator.
    #[must_use]
    pub fn into_inner(self) -> Vec<u8> {
        self.bytes
    }
}

/// Sanitizes an external error for MCP output and redacts exact secret values.
#[must_use]
pub fn sanitize_external_message(value: &str, max_bytes: usize, secrets: &[&str]) -> String {
    let mut sanitized = value
        .chars()
        .map(|character| if character.is_control() { ' ' } else { character })
        .collect::<String>();
    for secret in secrets.iter().copied().filter(|secret| !secret.is_empty()) {
        sanitized = sanitized.replace(secret, "[REDACTED]");
    }
    truncate_utf8(&sanitized, max_bytes, "…").into_owned()
}

/// Returns whether a candidate can safely be placed in an HTTP header value.
#[must_use]
pub fn valid_header_value(value: &str, max_bytes: usize) -> bool {
    !value.is_empty()
        && value.len() <= max_bytes
        && value
            .bytes()
            .all(|byte| matches!(byte, 0x21..=0x7e) && byte != b'\\')
}

/// Returns `true` for names that could identify secrets or users.
#[must_use]
pub fn is_sensitive_key(key: &str) -> bool {
    let normalized = key
        .to_ascii_lowercase()
        .replace(|character: char| matches!(character, '-' | '.'), "_");
    [
        "authorization",
        "bearer",
        "cookie",
        "credential",
        "email",
        "jwt",
        "passphrase",
        "passwd",
        "password",
        "private_key",
        "pwd",
        "secret",
        "session",
        "signing_key",
        "token",
        "api_key",
        "apikey",
    ]
    .iter()
    .any(|needle| normalized.contains(needle))
}

/// Returns `true` when a telemetry attribute key is bounded and portable.
#[must_use]
pub fn valid_attribute_key(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

/// Returns `true` when a telemetry attribute value is bounded and printable.
#[must_use]
pub fn valid_attribute_value(value: &str) -> bool {
    !value.is_empty() && value.len() <= 256 && !value.chars().any(char::is_control)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn truncation_preserves_utf8() {
        assert_eq!(truncate_utf8("ab😀cdef", 9, "…"), "ab😀…");
        assert_eq!(truncate_utf8("small", 10, "…"), "small");
    }

    #[test]
    fn sensitive_key_detection_is_fail_closed() {
        assert!(is_sensitive_key("http.request.header.authorization"));
        assert!(is_sensitive_key("api-token"));
        assert!(!is_sensitive_key("cloud.region"));
    }

    #[test]
    fn bounded_bytes_rejects_the_first_overflowing_chunk() {
        let mut bytes = BoundedBytes::new(1024).expect("valid bound");
        bytes
            .extend_from_slice(&vec![0_u8; 1024])
            .expect("exact boundary");
        assert!(bytes.extend_from_slice(&[1]).is_err());
        assert_eq!(bytes.len(), 1024);
    }

    #[test]
    fn external_messages_are_redacted_bounded_and_single_line() {
        let value = sanitize_external_message("token=supersecret\nfailed", 32, &["supersecret"]);
        assert_eq!(value, "token=[REDACTED] failed");
        assert!(valid_header_value("Bearerabc123", 64));
        assert!(!valid_header_value("bad header", 64));
    }

    #[test]
    fn bounds_reject_unbounded_values() {
        assert_eq!(Bounds::new(10, 2048), Err(BoundError::TextOutOfRange));
        assert_eq!(Bounds::new(2048, usize::MAX), Err(BoundError::JsonOutOfRange));
    }
}
