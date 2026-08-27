//! Secret-safe structured logging and optional OTLP lifecycle for Rust MCP servers.
//!
//! The crate deliberately has no `rmcp` dependency. Protocol-version-specific
//! tool-router wrapping remains in product adapters while this layer owns the
//! shared process telemetry boundary: stderr JSON logs, secret-safe resources,
//! optional OpenTelemetry 0.32 exporters, and bounded-cardinality tool labels.

#![forbid(unsafe_code)]

use std::{collections::BTreeMap, fmt};

use ore_mcp_bootstrap::{config::validate_log_filter_text, runtime::ServerIdentity};
use ore_mcp_safety::valid_attribute_value;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter, Layer};

mod endpoint;
#[cfg(feature = "otlp")]
mod otlp;
mod resource;
mod tool;

pub use endpoint::{
    OtlpEndpoint, TelemetryError, DEFAULT_LOG_FILTER, EXPORT_TIMEOUT, MAX_OTLP_ENDPOINT_BYTES,
    MAX_RESOURCE_ATTRIBUTES, MAX_TOOL_NAME_BYTES,
};
pub use resource::{reserved_resource_key, resource_attributes_from_snapshot};
pub use tool::{tool_span, validate_tool_name, ToolCall, ToolClass, ToolOutcome};

/// Fully validated telemetry startup configuration.
pub struct TelemetryConfig {
    identity: ServerIdentity,
    service_version: String,
    filter: EnvFilter,
    endpoint: Option<OtlpEndpoint>,
    resource_attributes: Vec<(String, String)>,
}

impl TelemetryConfig {
    /// Creates a stderr-only configuration with an optional explicit filter.
    ///
    /// A missing filter uses [`DEFAULT_LOG_FILTER`]. The service identity must
    /// already have been validated by `ore-mcp-bootstrap`.
    ///
    /// # Errors
    ///
    /// Returns a value-free error for an invalid service version or filter.
    pub fn new(
        identity: ServerIdentity,
        service_version: impl Into<String>,
        log_filter: Option<&str>,
    ) -> Result<Self, TelemetryError> {
        let service_version = service_version.into();
        if !valid_attribute_value(&service_version) {
            return Err(TelemetryError::InvalidServiceVersion);
        }

        let filter_text = log_filter.unwrap_or(DEFAULT_LOG_FILTER);
        let filter_text =
            validate_log_filter_text(filter_text).map_err(|_| TelemetryError::InvalidLogFilter)?;
        let filter =
            EnvFilter::try_new(filter_text).map_err(|_| TelemetryError::InvalidLogFilter)?;

        Ok(Self {
            identity,
            service_version,
            filter,
            endpoint: None,
            resource_attributes: Vec::new(),
        })
    }

    /// Adds an optional validated OTLP endpoint.
    ///
    /// `None` keeps trace and metric export disabled. Callers should map empty
    /// environment values to `None` before invoking this method.
    ///
    /// # Errors
    ///
    /// Returns [`TelemetryError::InvalidEndpoint`] for an invalid explicit value.
    pub fn with_otlp_endpoint(mut self, raw: Option<&str>) -> Result<Self, TelemetryError> {
        self.endpoint = raw.map(OtlpEndpoint::parse).transpose()?;
        Ok(self)
    }

    /// Replaces safe resource attributes from an explicit environment snapshot.
    #[must_use]
    pub fn with_resource_snapshot(mut self, snapshot: &BTreeMap<String, String>) -> Self {
        self.resource_attributes = resource_attributes_from_snapshot(snapshot);
        self
    }

    /// Returns whether an OTLP endpoint is explicitly configured.
    #[must_use]
    pub fn endpoint_present(&self) -> bool {
        self.endpoint.is_some()
    }

    /// Returns the validated canonical service identity.
    #[must_use]
    pub fn identity(&self) -> &ServerIdentity {
        &self.identity
    }

    /// Returns the validated service version.
    #[must_use]
    pub fn service_version(&self) -> &str {
        &self.service_version
    }

    /// Returns the accepted resource-attribute keys without exposing values.
    pub fn resource_attribute_keys(&self) -> impl Iterator<Item = &str> {
        self.resource_attributes.iter().map(|(key, _)| key.as_str())
    }

    /// Returns the validated collector endpoint when one was configured.
    #[cfg(feature = "otlp")]
    pub(crate) fn endpoint(&self) -> Option<&OtlpEndpoint> {
        self.endpoint.as_ref()
    }

    /// Returns accepted resource pairs for SDK resource assembly.
    #[cfg(feature = "otlp")]
    pub(crate) fn resource_attributes(&self) -> &[(String, String)] {
        &self.resource_attributes
    }
}

impl fmt::Debug for TelemetryConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TelemetryConfig")
            .field("identity", &self.identity)
            .field("service_version", &self.service_version)
            .field("log_filter", &"<validated>")
            .field("endpoint_present", &self.endpoint.is_some())
            .field(
                "resource_attribute_keys",
                &self.resource_attribute_keys().collect::<Vec<_>>(),
            )
            .finish()
    }
}

/// Structured-log destination selected by this crate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LogDestination {
    /// JSON logs are written to standard error, preserving MCP stdout purity.
    Stderr,
}

/// Result of attempting to install the process-global tracing subscriber.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SubscriberState {
    /// This call installed the stderr subscriber.
    Installed,
    /// A subscriber already existed, so this call left it unchanged.
    Existing,
}

/// State of one optional OTLP exporter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExporterState {
    /// No endpoint was configured, or the `otlp` feature is disabled.
    Disabled,
    /// The exporter was built and activated.
    Enabled,
    /// Exporter construction failed; stderr logging remains active.
    BuildFailed,
    /// A pre-existing subscriber prevented this crate from activating providers.
    Suppressed,
}

/// Value-free telemetry activation status.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TelemetryStatus {
    /// Structured-log destination.
    pub log_destination: LogDestination,
    /// Subscriber installation state.
    pub subscriber: SubscriberState,
    /// Trace exporter state.
    pub traces: ExporterState,
    /// Metric exporter state.
    pub metrics: ExporterState,
}

/// Result of explicitly flushing retained providers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ShutdownStatus {
    /// No providers were active.
    NoExporters,
    /// Every active provider shut down successfully.
    Flushed,
    /// At least one provider reported a shutdown failure.
    Partial,
    /// The dedicated shutdown thread panicked.
    Panicked,
}

/// Owns active providers until MCP protocol shutdown.
pub struct TelemetryGuard {
    #[cfg(feature = "otlp")]
    tracer_provider: Option<opentelemetry_sdk::trace::SdkTracerProvider>,
    #[cfg(feature = "otlp")]
    meter_provider: Option<opentelemetry_sdk::metrics::SdkMeterProvider>,
    status: TelemetryStatus,
}

impl TelemetryGuard {
    /// Returns value-free activation status.
    #[must_use]
    pub const fn status(&self) -> TelemetryStatus {
        self.status
    }

    /// Flushes active providers and consumes the guard.
    #[must_use]
    pub fn shutdown(mut self) -> ShutdownStatus {
        self.shutdown_inner()
    }

    fn shutdown_inner(&mut self) -> ShutdownStatus {
        #[cfg(feature = "otlp")]
        {
            otlp::shutdown_providers(self.tracer_provider.take(), self.meter_provider.take())
        }
        #[cfg(not(feature = "otlp"))]
        ShutdownStatus::NoExporters
    }
}

impl fmt::Debug for TelemetryGuard {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut debug = formatter.debug_struct("TelemetryGuard");
        debug.field("status", &self.status);
        #[cfg(feature = "otlp")]
        {
            debug.field("tracer_provider_retained", &self.tracer_provider.is_some());
            debug.field("meter_provider_retained", &self.meter_provider.is_some());
        }
        debug.finish()
    }
}

impl Drop for TelemetryGuard {
    fn drop(&mut self) {
        let _ = self.shutdown_inner();
    }
}

/// Installs stderr JSON logging and optional OTLP providers.
///
/// Exporter construction failures are represented only in [`TelemetryStatus`]
/// and do not prevent stderr logging. When a subscriber already exists, this
/// function leaves it and the global OpenTelemetry providers unchanged.
#[must_use]
pub fn init(config: TelemetryConfig) -> TelemetryGuard {
    #[cfg(feature = "otlp")]
    {
        init_with_otlp(config)
    }
    #[cfg(not(feature = "otlp"))]
    {
        init_stderr_only(config)
    }
}

#[cfg(not(feature = "otlp"))]
fn init_stderr_only(config: TelemetryConfig) -> TelemetryGuard {
    let subscriber = install_subscriber(config.filter, None);
    if subscriber == SubscriberState::Installed {
        tracing::info!(
            service.name = config.identity.service_name(),
            service.namespace = config.identity.service_namespace(),
            service.version = config.service_version.as_str(),
            mcp.transport = config.identity.transport(),
            otel.trace_exporter = ?ExporterState::Disabled,
            otel.metric_exporter = ?ExporterState::Disabled,
            log.stream = "stderr",
            "MCP telemetry initialized"
        );
    }
    TelemetryGuard {
        #[cfg(feature = "otlp")]
        tracer_provider: None,
        #[cfg(feature = "otlp")]
        meter_provider: None,
        status: TelemetryStatus {
            log_destination: LogDestination::Stderr,
            subscriber,
            traces: ExporterState::Disabled,
            metrics: ExporterState::Disabled,
        },
    }
}

#[cfg(feature = "otlp")]
fn init_with_otlp(config: TelemetryConfig) -> TelemetryGuard {
    let mut providers = otlp::build_provider_bundle(&config);
    let subscriber = install_subscriber(config.filter, providers.tracer.take());
    if subscriber == SubscriberState::Installed {
        otlp::install_globals(&providers);
        tracing::info!(
            service.name = config.identity.service_name(),
            service.namespace = config.identity.service_namespace(),
            service.version = config.service_version.as_str(),
            mcp.transport = config.identity.transport(),
            otel.trace_exporter = ?providers.traces,
            otel.metric_exporter = ?providers.metrics,
            log.stream = "stderr",
            "MCP telemetry initialized"
        );
    } else {
        let trace_built = providers.tracer_provider.is_some();
        let metric_built = providers.meter_provider.is_some();
        let _ = otlp::shutdown_providers(
            providers.tracer_provider.take(),
            providers.meter_provider.take(),
        );
        if trace_built {
            providers.traces = ExporterState::Suppressed;
        }
        if metric_built {
            providers.metrics = ExporterState::Suppressed;
        }
    }

    TelemetryGuard {
        tracer_provider: providers.tracer_provider,
        meter_provider: providers.meter_provider,
        status: TelemetryStatus {
            log_destination: LogDestination::Stderr,
            subscriber,
            traces: providers.traces,
            metrics: providers.metrics,
        },
    }
}

fn install_subscriber(
    filter: EnvFilter,
    #[cfg(feature = "otlp")] tracer: Option<opentelemetry_sdk::trace::SdkTracer>,
    #[cfg(not(feature = "otlp"))] tracer: Option<()>,
) -> SubscriberState {
    let result = match tracer {
        #[cfg(feature = "otlp")]
        Some(tracer) => tracing_subscriber::registry()
            .with(filter)
            .with(stderr_json_layer())
            .with(otlp::tracing_layer(tracer))
            .try_init(),
        #[cfg(not(feature = "otlp"))]
        Some(()) => tracing_subscriber::registry()
            .with(filter)
            .with(stderr_json_layer())
            .try_init(),
        None => tracing_subscriber::registry()
            .with(filter)
            .with(stderr_json_layer())
            .try_init(),
    };
    if result.is_ok() {
        SubscriberState::Installed
    } else {
        SubscriberState::Existing
    }
}

fn stderr_json_layer<S>() -> impl Layer<S>
where
    S: tracing::Subscriber + for<'lookup> tracing_subscriber::registry::LookupSpan<'lookup>,
{
    tracing_subscriber::fmt::layer()
        .json()
        .flatten_event(true)
        .with_ansi(false)
        .with_current_span(true)
        .with_span_list(true)
        .with_target(true)
        .with_writer(std::io::stderr)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity() -> ServerIdentity {
        ServerIdentity::stdio("telemetry-test", "ore-test").expect("valid static identity")
    }

    #[test]
    fn endpoint_accepts_bounded_http_collectors() {
        let endpoint = OtlpEndpoint::parse(" https://collector.example:4317/v1/otlp ")
            .expect("valid collector");
        assert_eq!(endpoint.as_str(), "https://collector.example:4317/v1/otlp");
        assert_eq!(format!("{endpoint:?}"), "OtlpEndpoint(\"<validated>\")");
        assert!(OtlpEndpoint::parse("http://127.0.0.1:4317").is_ok());
    }

    #[test]
    fn endpoint_rejects_credentials_queries_fragments_controls_and_schemes() {
        for endpoint in [
            "",
            "https://user:secret@collector.example:4317",
            "https://collector.example:4317?token=secret",
            "https://collector.example:4317#fragment",
            "file:///tmp/otel.sock",
            "collector.example:4317",
            "https://collector.example/line\nfeed",
        ] {
            assert_eq!(
                OtlpEndpoint::parse(endpoint),
                Err(TelemetryError::InvalidEndpoint)
            );
        }
        assert_eq!(
            OtlpEndpoint::parse(&format!(
                "https://collector.example/{}",
                "x".repeat(MAX_OTLP_ENDPOINT_BYTES)
            )),
            Err(TelemetryError::InvalidEndpoint)
        );
    }

    #[test]
    fn resource_snapshot_is_bounded_deduplicated_and_runtime_owned() {
        let snapshot = BTreeMap::from([
            ("DEPLOYMENT_ENV".to_string(), "production".to_string()),
            ("POD_NAME".to_string(), "mcp-0".to_string()),
            (
                "OTEL_RESOURCE_ATTRIBUTES".to_string(),
                "team=platform,api.token=nope,service.name=spoof,deployment.environment=spoof,cloud.region=us-east-1,team=duplicate"
                    .to_string(),
            ),
        ]);
        assert_eq!(
            resource_attributes_from_snapshot(&snapshot),
            vec![
                (
                    "deployment.environment".to_string(),
                    "production".to_string()
                ),
                ("k8s.pod.name".to_string(), "mcp-0".to_string()),
                ("team".to_string(), "platform".to_string()),
                ("cloud.region".to_string(), "us-east-1".to_string()),
            ]
        );
        for key in [
            "service.name",
            "service.namespace",
            "service.version",
            "mcp.transport",
            "deployment.environment",
            "host.name",
        ] {
            assert!(reserved_resource_key(key));
        }
        assert!(!reserved_resource_key("cloud.region"));
    }

    #[test]
    fn configuration_errors_and_debug_never_retain_values() {
        assert_eq!(
            TelemetryConfig::new(identity(), "0.1.0", Some("info\nprivate"))
                .expect_err("control-bearing filter must fail"),
            TelemetryError::InvalidLogFilter
        );
        assert_eq!(
            TelemetryConfig::new(identity(), "bad\nversion", None)
                .expect_err("control-bearing version must fail"),
            TelemetryError::InvalidServiceVersion
        );

        let snapshot = BTreeMap::from([
            ("POD_NAME".to_string(), "private-pod-value".to_string()),
            (
                "OTEL_RESOURCE_ATTRIBUTES".to_string(),
                "team=private-team-value".to_string(),
            ),
        ]);
        let config = TelemetryConfig::new(identity(), "0.1.0", Some("debug,hyper=warn"))
            .expect("valid configuration")
            .with_resource_snapshot(&snapshot)
            .with_otlp_endpoint(Some("https://collector.example/private-path"))
            .expect("valid endpoint");
        let debug = format!("{config:?}");
        assert!(debug.contains("endpoint_present"));
        assert!(debug.contains("k8s.pod.name"));
        assert!(debug.contains("team"));
        for private in [
            "private-pod-value",
            "private-team-value",
            "private-path",
            "debug,hyper=warn",
        ] {
            assert!(!debug.contains(private));
        }
    }

    #[test]
    fn tool_names_and_spans_are_bounded_and_payload_free() {
        assert_eq!(validate_tool_name("org_identity"), Ok("org_identity"));
        assert_eq!(
            validate_tool_name("api.token"),
            Err(TelemetryError::InvalidToolName)
        );
        assert_eq!(
            validate_tool_name("tool with spaces"),
            Err(TelemetryError::InvalidToolName)
        );
        assert_eq!(
            validate_tool_name(&"x".repeat(MAX_TOOL_NAME_BYTES + 1)),
            Err(TelemetryError::InvalidToolName)
        );

        let span = tool_span("org_identity", ToolClass::Inventory).expect("valid tool");
        let debug = format!("{span:?}");
        assert!(!debug.to_ascii_lowercase().contains("argument"));
        assert!(!debug.to_ascii_lowercase().contains("result"));
        assert!(!debug.to_ascii_lowercase().contains("secret"));

        let call = ToolCall::start("telemetry_status", ToolClass::Health).expect("valid tool");
        assert_eq!(call.name(), "telemetry_status");
        assert_eq!(call.class(), ToolClass::Health);
        call.finish(ToolOutcome::Ok);
    }

    #[test]
    fn stderr_fallback_and_existing_subscriber_are_explicit() {
        let first = init(
            TelemetryConfig::new(identity(), "0.1.0", Some("off"))
                .expect("valid stderr-only configuration"),
        );
        assert_eq!(
            first.status(),
            TelemetryStatus {
                log_destination: LogDestination::Stderr,
                subscriber: SubscriberState::Installed,
                traces: ExporterState::Disabled,
                metrics: ExporterState::Disabled,
            }
        );

        let second = init(
            TelemetryConfig::new(identity(), "0.1.0", Some("off"))
                .expect("valid second configuration"),
        );
        assert_eq!(second.status().log_destination, LogDestination::Stderr);
        assert_eq!(second.status().subscriber, SubscriberState::Existing);
        assert_eq!(second.shutdown(), ShutdownStatus::NoExporters);
        assert_eq!(first.shutdown(), ShutdownStatus::NoExporters);
    }

    #[cfg(feature = "otlp")]
    #[test]
    fn provider_build_failures_are_status_only_and_fail_open() {
        let endpoint =
            OtlpEndpoint::parse("https://collector.example:4317").expect("valid endpoint");
        let resource = otlp::sdk_resource(
            &TelemetryConfig::new(identity(), "0.1.0", None).expect("valid configuration"),
        );
        let bundle = otlp::build_provider_bundle_with(
            Some(&endpoint),
            resource,
            |_, _| {
                Err::<
                    (
                        opentelemetry_sdk::trace::SdkTracerProvider,
                        opentelemetry_sdk::trace::SdkTracer,
                    ),
                    (),
                >(())
            },
            |_, _| Err::<opentelemetry_sdk::metrics::SdkMeterProvider, ()>(()),
        );
        assert_eq!(bundle.traces, ExporterState::BuildFailed);
        assert_eq!(bundle.metrics, ExporterState::BuildFailed);
        assert!(bundle.tracer_provider.is_none());
        assert!(bundle.meter_provider.is_none());
        assert!(bundle.tracer.is_none());
    }

    #[cfg(feature = "otlp")]
    #[test]
    fn endpoint_without_tokio_runtime_fails_open_without_panicking() {
        let endpoint =
            OtlpEndpoint::parse("https://collector.example:4317").expect("valid endpoint");
        let resource = otlp::sdk_resource(
            &TelemetryConfig::new(identity(), "0.1.0", None).expect("valid configuration"),
        );
        let bundle = otlp::build_provider_bundle_with(
            Some(&endpoint),
            resource,
            otlp::build_tracer_provider,
            otlp::build_meter_provider,
        );
        assert_eq!(bundle.traces, ExporterState::BuildFailed);
        assert_eq!(bundle.metrics, ExporterState::BuildFailed);
        assert!(bundle.tracer_provider.is_none());
        assert!(bundle.meter_provider.is_none());
    }
}
