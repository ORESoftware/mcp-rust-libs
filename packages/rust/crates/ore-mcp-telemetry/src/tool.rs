use std::time::Instant;

use ore_mcp_safety::{is_sensitive_key, valid_attribute_key};

use crate::endpoint::{TelemetryError, MAX_TOOL_NAME_BYTES};

/// Closed MCP tool classes used as low-cardinality span and metric attributes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ToolClass {
    /// Inventory and identity tools.
    Inventory,
    /// Health and status tools.
    Health,
    /// Read-only detail or policy tools.
    Details,
    /// Other non-mutating observation tools.
    Read,
}

impl ToolClass {
    /// Returns the stable telemetry label for this class.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Inventory => "inventory",
            Self::Health => "health",
            Self::Details => "details",
            Self::Read => "read",
        }
    }
}

/// Closed tool-call outcomes recorded without result bodies.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ToolOutcome {
    /// The tool completed without an application error.
    Ok,
    /// The tool failed or the transport returned an error.
    Error,
}

impl ToolOutcome {
    /// Returns the OpenTelemetry status label for this outcome.
    #[must_use]
    pub const fn status_code(self) -> &'static str {
        match self {
            Self::Ok => "OK",
            Self::Error => "ERROR",
        }
    }

    /// Returns whether the call is classified as an error.
    #[must_use]
    pub const fn is_error(self) -> bool {
        matches!(self, Self::Error)
    }
}

/// Validates one MCP tool name before it is used as a telemetry attribute.
///
/// # Errors
///
/// Returns [`TelemetryError::InvalidToolName`] for empty, oversized,
/// non-portable, or secret-shaped names. The rejected value is not retained.
pub fn validate_tool_name(name: &str) -> Result<&str, TelemetryError> {
    let name = name.trim();
    if name.is_empty()
        || name.len() > MAX_TOOL_NAME_BYTES
        || !valid_attribute_key(name)
        || is_sensitive_key(name)
    {
        return Err(TelemetryError::InvalidToolName);
    }
    Ok(name)
}

/// Builds a low-cardinality tool span that never records arguments or results.
///
/// # Errors
///
/// Returns [`TelemetryError::InvalidToolName`] when the tool name is not a
/// bounded portable token.
pub fn tool_span(name: &str, class: ToolClass) -> Result<tracing::Span, TelemetryError> {
    let name = validate_tool_name(name)?;
    Ok(tracing::info_span!(
        "mcp.tool.call",
        rpc.system = "mcp",
        rpc.method = "tools/call",
        mcp.tool.name = name,
        mcp.tool.class = class.as_str(),
        otel.status_code = tracing::field::Empty,
        mcp.tool.error = tracing::field::Empty,
    ))
}

/// Records duration and outcome for one tool call without capturing payloads.
pub struct ToolCall {
    name: String,
    class: ToolClass,
    started: Instant,
}

impl ToolCall {
    /// Starts a bounded tool observation.
    ///
    /// # Errors
    ///
    /// Returns [`TelemetryError::InvalidToolName`] when the name is invalid.
    pub fn start(name: &str, class: ToolClass) -> Result<Self, TelemetryError> {
        Ok(Self {
            name: validate_tool_name(name)?.to_string(),
            class,
            started: Instant::now(),
        })
    }

    /// Returns the validated tool name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the closed tool class.
    #[must_use]
    pub const fn class(&self) -> ToolClass {
        self.class
    }

    /// Completes the observation with a closed outcome label.
    ///
    /// Duration is retained only as a metric when the `otlp` feature is enabled.
    /// Arguments, results, credentials, and user identity are never recorded.
    pub fn finish(self, outcome: ToolOutcome) {
        let elapsed_ms = self.started.elapsed().as_secs_f64() * 1_000.0;
        tracing::Span::current().record("otel.status_code", outcome.status_code());
        tracing::Span::current().record("mcp.tool.error", outcome.is_error());
        #[cfg(feature = "otlp")]
        record_tool_metrics(&self.name, self.class, outcome, elapsed_ms);
        #[cfg(not(feature = "otlp"))]
        let _ = elapsed_ms;
    }
}

#[cfg(feature = "otlp")]
fn record_tool_metrics(name: &str, class: ToolClass, outcome: ToolOutcome, elapsed_ms: f64) {
    use opentelemetry::{global, KeyValue};

    let meter = global::meter("ore-mcp-telemetry");
    let calls = meter
        .u64_counter("mcp.server.tool.calls")
        .with_description("Number of MCP tool calls completed")
        .with_unit("{call}")
        .build();
    let duration = meter
        .f64_histogram("mcp.server.tool.duration")
        .with_description("MCP tool call duration")
        .with_unit("ms")
        .build();
    let attributes = [
        KeyValue::new("mcp.tool.name", name.to_string()),
        KeyValue::new("mcp.tool.class", class.as_str()),
        KeyValue::new("mcp.tool.error", outcome.is_error()),
    ];
    calls.add(1, &attributes);
    duration.record(elapsed_ms, &attributes);
}
