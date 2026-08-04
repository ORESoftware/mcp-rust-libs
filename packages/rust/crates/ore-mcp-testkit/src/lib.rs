//! Runtime-independent helpers for MCP process and fleet conformance tests.

#![forbid(unsafe_code)]

mod session;

use std::{fmt, str};

pub use session::{
    audit_closed_world_tool_catalog_response, audit_initialize_response,
    audit_text_tool_result_response, InitializeAudit, SessionAuditError, ToolCatalogAudit,
    ToolResultAudit,
};

/// Summary from auditing one stdio process output stream.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FrameAudit {
    /// Number of non-empty protocol frames observed.
    pub frame_count: usize,
    /// Number of JSON-RPC responses observed.
    pub response_count: usize,
    /// Number of JSON-RPC notifications observed.
    pub notification_count: usize,
}

/// Stdio protocol purity failures.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FrameAuditError {
    /// Stdout was not valid UTF-8.
    NonUtf8,
    /// Total stdout exceeded the configured bound.
    OutputTooLarge,
    /// More frames were emitted than permitted.
    TooManyFrames,
    /// A non-empty line was not a JSON object.
    NonJsonObject {
        /// One-based line number.
        line: usize,
    },
    /// A line did not identify JSON-RPC 2.0 exactly.
    MissingJsonRpcVersion {
        /// One-based line number.
        line: usize,
    },
    /// A frame was neither a response nor a notification/request.
    InvalidEnvelopeShape {
        /// One-based line number.
        line: usize,
    },
    /// A NUL byte was present.
    NulByte {
        /// One-based line number.
        line: usize,
    },
    /// The process returned no protocol frames.
    Empty,
}

impl fmt::Display for FrameAuditError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for FrameAuditError {}

/// Audits newline-delimited stdio output using conservative defaults.
///
/// # Errors
///
/// Delegates to [`audit_stdio_stdout_with_limits`].
pub fn audit_stdio_stdout(bytes: &[u8]) -> Result<FrameAudit, FrameAuditError> {
    audit_stdio_stdout_with_limits(bytes, 4 * 1024 * 1024, 10_000)
}

/// Audits newline-delimited stdio output semantically and under explicit limits.
///
/// # Errors
///
/// Rejects invalid UTF-8, oversized output, excessive frames, non-object JSON,
/// non-exact JSON-RPC versions, NUL bytes, malformed envelope shapes, and empty
/// output.
pub fn audit_stdio_stdout_with_limits(
    bytes: &[u8],
    max_bytes: usize,
    max_frames: usize,
) -> Result<FrameAudit, FrameAuditError> {
    if bytes.len() > max_bytes {
        return Err(FrameAuditError::OutputTooLarge);
    }
    let text = str::from_utf8(bytes).map_err(|_| FrameAuditError::NonUtf8)?;
    let mut frame_count = 0;
    let mut response_count = 0;
    let mut notification_count = 0;
    for (index, line) in text.lines().enumerate() {
        let line_number = index + 1;
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if trimmed.as_bytes().contains(&0) {
            return Err(FrameAuditError::NulByte { line: line_number });
        }
        let value: serde_json::Value = serde_json::from_str(trimmed)
            .map_err(|_| FrameAuditError::NonJsonObject { line: line_number })?;
        let object = value
            .as_object()
            .ok_or(FrameAuditError::NonJsonObject { line: line_number })?;
        if object.get("jsonrpc").and_then(serde_json::Value::as_str) != Some("2.0") {
            return Err(FrameAuditError::MissingJsonRpcVersion { line: line_number });
        }
        let has_method = object
            .get("method")
            .and_then(serde_json::Value::as_str)
            .is_some();
        let has_result_or_error = object.contains_key("result") ^ object.contains_key("error");
        if has_method {
            notification_count += 1;
        } else if object.contains_key("id") && has_result_or_error {
            response_count += 1;
        } else {
            return Err(FrameAuditError::InvalidEnvelopeShape { line: line_number });
        }
        frame_count += 1;
        if frame_count > max_frames {
            return Err(FrameAuditError::TooManyFrames);
        }
    }
    if frame_count == 0 {
        return Err(FrameAuditError::Empty);
    }
    Ok(FrameAudit {
        frame_count,
        response_count,
        notification_count,
    })
}

/// Machine-readable result for one fleet repository.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FleetResult {
    /// `owner/repository` identity.
    pub repository: String,
    /// Whether conformance passed.
    pub passed: bool,
    /// Bounded, sanitized failure code when `passed` is false.
    pub failure_code: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pure_protocol_output_passes() {
        let audit = audit_stdio_stdout(
            b"{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}\n{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}\n",
        )
        .expect("valid frames");
        assert_eq!(audit.frame_count, 2);
        assert_eq!(audit.response_count, 1);
        assert_eq!(audit.notification_count, 1);
    }

    #[test]
    fn spoofed_markers_and_log_pollution_are_rejected() {
        assert_eq!(
            audit_stdio_stdout(b"starting server\n"),
            Err(FrameAuditError::NonJsonObject { line: 1 })
        );
        assert_eq!(
            audit_stdio_stdout(b"{\"note\":\"jsonrpc 2.0\"}\n"),
            Err(FrameAuditError::MissingJsonRpcVersion { line: 1 })
        );
    }

    #[test]
    fn limits_fail_before_unbounded_test_processing() {
        assert_eq!(
            audit_stdio_stdout_with_limits(b"12345", 4, 10),
            Err(FrameAuditError::OutputTooLarge)
        );
        let frames =
            b"{\"jsonrpc\":\"2.0\",\"method\":\"one\"}\n{\"jsonrpc\":\"2.0\",\"method\":\"two\"}\n";
        assert_eq!(
            audit_stdio_stdout_with_limits(frames, 1024, 1),
            Err(FrameAuditError::TooManyFrames)
        );
    }
}
