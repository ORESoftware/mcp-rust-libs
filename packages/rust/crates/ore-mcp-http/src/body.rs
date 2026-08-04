//! Incremental response-body bounds for HTTP-client adapters.

use std::{error::Error, fmt};

use ore_mcp_safety::{BoundError, BoundedBytes};

/// Incremental response body that never retains bytes beyond a fixed ceiling.
///
/// Concrete clients keep ownership of transport-specific streaming and timeout
/// behavior. This type centralizes the content-length preflight and byte-limit
/// accounting that had been copied across the MCP fleet.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BoundedBody {
    limit: usize,
    bytes: BoundedBytes,
}

impl BoundedBody {
    /// Creates an empty response accumulator.
    ///
    /// # Errors
    ///
    /// Returns [`BodyLimitError::InvalidLimit`] unless the limit is between
    /// 1 KiB and 16 MiB, matching the shared safety primitive.
    pub fn new(limit: usize) -> Result<Self, BodyLimitError> {
        let bytes = BoundedBytes::new(limit).map_err(|_| BodyLimitError::InvalidLimit)?;
        Ok(Self { limit, bytes })
    }

    /// Creates an accumulator after checking an optional declared body length.
    ///
    /// A missing length is accepted because chunked and HTTP/2 bodies commonly
    /// omit it. A declared value larger than the configured ceiling is rejected
    /// before any body bytes are read.
    ///
    /// # Errors
    ///
    /// Returns [`BodyLimitError::DeclaredTooLarge`] when `content_length`
    /// exceeds `limit`, or [`BodyLimitError::InvalidLimit`] for an unsupported
    /// limit.
    pub fn preflight(
        limit: usize,
        content_length: Option<u64>,
    ) -> Result<Self, BodyLimitError> {
        if content_length.is_some_and(|length| length > limit as u64) {
            return Err(BodyLimitError::DeclaredTooLarge);
        }
        Self::new(limit)
    }

    /// Appends one transport chunk.
    ///
    /// The first chunk that would exceed the ceiling is rejected and no prefix
    /// of that chunk is retained.
    ///
    /// # Errors
    ///
    /// Returns [`BodyLimitError::StreamedTooLarge`] when the accumulated body
    /// would exceed the configured limit or length arithmetic overflows.
    pub fn push(&mut self, chunk: &[u8]) -> Result<(), BodyLimitError> {
        self.bytes
            .extend_from_slice(chunk)
            .map_err(|_| BodyLimitError::StreamedTooLarge)
    }

    /// Returns the configured byte ceiling.
    #[must_use]
    pub const fn limit(&self) -> usize {
        self.limit
    }

    /// Returns the number of retained bytes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Returns whether no body bytes have been retained.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// Consumes the accumulator and returns the bounded body.
    #[must_use]
    pub fn into_inner(self) -> Vec<u8> {
        self.bytes.into_inner()
    }
}

/// Fail-closed body-bound errors suitable for sanitized error mapping.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BodyLimitError {
    /// The configured ceiling is outside the supported range.
    InvalidLimit,
    /// A declared content length already exceeds the ceiling.
    DeclaredTooLarge,
    /// Incremental streaming crossed the ceiling.
    StreamedTooLarge,
}

impl fmt::Display for BodyLimitError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLimit => formatter.write_str("invalid HTTP response body limit"),
            Self::DeclaredTooLarge => {
                formatter.write_str("declared HTTP response body exceeds the configured limit")
            }
            Self::StreamedTooLarge => {
                formatter.write_str("streamed HTTP response body exceeds the configured limit")
            }
        }
    }
}

impl Error for BodyLimitError {}

impl From<BoundError> for BodyLimitError {
    fn from(_: BoundError) -> Self {
        Self::InvalidLimit
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn declared_oversize_is_rejected_before_streaming() {
        assert_eq!(
            BoundedBody::preflight(1024, Some(1025)),
            Err(BodyLimitError::DeclaredTooLarge)
        );
        assert!(BoundedBody::preflight(1024, None).is_ok());
        assert!(BoundedBody::preflight(1024, Some(1024)).is_ok());
    }

    #[test]
    fn exact_boundary_is_accepted() {
        let mut body = BoundedBody::new(1024).expect("valid limit");
        body.push(&vec![7_u8; 512]).expect("first half");
        body.push(&vec![8_u8; 512]).expect("second half");
        assert_eq!(body.len(), 1024);
        assert_eq!(body.limit(), 1024);
        assert_eq!(body.into_inner().len(), 1024);
    }

    #[test]
    fn overflowing_chunk_is_not_partially_retained() {
        let mut body = BoundedBody::new(1024).expect("valid limit");
        body.push(&vec![1_u8; 1000]).expect("prefix fits");
        assert_eq!(
            body.push(&vec![2_u8; 25]),
            Err(BodyLimitError::StreamedTooLarge)
        );
        assert_eq!(body.len(), 1000);
    }

    #[test]
    fn unsupported_limits_fail_closed() {
        assert_eq!(
            BoundedBody::new(1023),
            Err(BodyLimitError::InvalidLimit)
        );
        assert_eq!(
            BoundedBody::new(16 * 1024 * 1024 + 1),
            Err(BodyLimitError::InvalidLimit)
        );
    }
}
