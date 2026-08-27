use std::{error::Error, fmt, time::Duration};

use url::Url;

/// Default stderr filter used when callers do not provide one explicitly.
pub const DEFAULT_LOG_FILTER: &str = "info,hyper=warn,tonic=warn";
/// Maximum accepted OTLP endpoint bytes.
pub const MAX_OTLP_ENDPOINT_BYTES: usize = 2 * 1024;
/// Maximum safe resource attributes accepted from one caller snapshot.
pub const MAX_RESOURCE_ATTRIBUTES: usize = 32;
/// Maximum exporter construction and request timeout.
pub const EXPORT_TIMEOUT: Duration = Duration::from_secs(5);
/// Maximum accepted MCP tool name bytes.
pub const MAX_TOOL_NAME_BYTES: usize = 64;

/// Validated OTLP collector endpoint.
#[derive(Clone, Eq, PartialEq)]
pub struct OtlpEndpoint(String);

impl OtlpEndpoint {
    /// Parses one bounded HTTP(S) collector endpoint.
    ///
    /// Paths are allowed. Embedded credentials, query parameters, fragments,
    /// control characters, missing hosts, and non-HTTP schemes are rejected.
    ///
    /// # Errors
    ///
    /// Returns [`TelemetryError::InvalidEndpoint`] without retaining the raw
    /// endpoint in the error.
    pub fn parse(raw: &str) -> Result<Self, TelemetryError> {
        let endpoint = raw.trim();
        if endpoint.is_empty()
            || endpoint.len() > MAX_OTLP_ENDPOINT_BYTES
            || endpoint.chars().any(char::is_control)
        {
            return Err(TelemetryError::InvalidEndpoint);
        }

        let parsed = Url::parse(endpoint).map_err(|_| TelemetryError::InvalidEndpoint)?;
        if !matches!(parsed.scheme(), "http" | "https")
            || parsed.host_str().is_none()
            || !parsed.username().is_empty()
            || parsed.password().is_some()
            || parsed.query().is_some()
            || parsed.fragment().is_some()
        {
            return Err(TelemetryError::InvalidEndpoint);
        }

        Ok(Self(endpoint.to_string()))
    }

    /// Returns the validated endpoint for exporter construction.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for OtlpEndpoint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("OtlpEndpoint")
            .field(&"<validated>")
            .finish()
    }
}

/// Telemetry configuration errors that never retain caller values.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TelemetryError {
    /// The service version was empty, oversized, or control-bearing.
    InvalidServiceVersion,
    /// The log filter failed bounded-text or `EnvFilter` validation.
    InvalidLogFilter,
    /// The OTLP endpoint failed the strict collector policy.
    InvalidEndpoint,
    /// A tool name was empty, oversized, control-bearing, or secret-shaped.
    InvalidToolName,
}

impl fmt::Display for TelemetryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidServiceVersion => formatter.write_str("invalid telemetry service version"),
            Self::InvalidLogFilter => formatter.write_str("invalid telemetry log filter"),
            Self::InvalidEndpoint => formatter.write_str("invalid OTLP collector endpoint"),
            Self::InvalidToolName => formatter.write_str("invalid MCP tool name"),
        }
    }
}

impl Error for TelemetryError {}
