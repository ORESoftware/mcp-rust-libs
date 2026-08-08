//! Secret-safe structured logging and optional OTLP lifecycle for Rust MCP servers.
//!
//! The crate deliberately has no `rmcp` dependency. Protocol-version-specific
//! tool instrumentation remains in product adapters while this layer owns the
//! shared process telemetry boundary.

#![forbid(unsafe_code)]

use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    fmt,
    time::Duration,
};

use opentelemetry::{KeyValue, global};
use opentelemetry_otlp::WithExportConfig;
use opentelemetry_sdk::{
    Resource,
    metrics::{PeriodicReader, SdkMeterProvider},
    runtime,
    trace::{Tracer, TracerProvider},
};
use ore_mcp_bootstrap::{
    config::validate_log_filter_text,
    runtime::ServerIdentity,
    telemetry::{STANDARD_RESOURCE_ENV, reserved_identity_key, resource_attribute_pairs},
};
use ore_mcp_safety::valid_attribute_value;
use tracing_subscriber::{EnvFilter, layer::SubscriberExt, util::SubscriberInitExt};
use url::Url;

/// Default stderr filter used when callers do not provide one explicitly.
pub const DEFAULT_LOG_FILTER: &str = "info,hyper=warn,tonic=warn";
/// Maximum accepted OTLP endpoint bytes.
pub const MAX_OTLP_ENDPOINT_BYTES: usize = 2 * 1024;
/// Maximum safe resource attributes accepted from one caller snapshot.
pub const MAX_RESOURCE_ATTRIBUTES: usize = 32;
/// Maximum exporter construction and request timeout.
pub const EXPORT_TIMEOUT: Duration = Duration::from_secs(5);

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
}

impl fmt::Display for TelemetryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidServiceVersion => formatter.write_str("invalid telemetry service version"),
            Self::InvalidLogFilter => formatter.write_str("invalid telemetry log filter"),
            Self::InvalidEndpoint => formatter.write_str("invalid OTLP collector endpoint"),
        }
    }
}

impl Error for TelemetryError {}

/// Returns whether a resource key is owned by the shared runtime.
///
/// Custom `OTEL_RESOURCE_ATTRIBUTES` values cannot replace these fields.
#[must_use]
pub fn reserved_resource_key(key: &str) -> bool {
    reserved_identity_key(key)
        || key == "mcp.transport"
        || STANDARD_RESOURCE_ENV
            .iter()
            .any(|(_, resource_key)| *resource_key == key)
}

/// Builds deterministic, bounded resource attributes from an explicit snapshot.
///
/// The snapshot may contain the five fleet-standard environment names and an
/// `OTEL_RESOURCE_ATTRIBUTES` entry. Invalid values, sensitive keys, duplicate
/// keys, and runtime-owned fields are ignored without logging their contents.
#[must_use]
pub fn resource_attributes_from_snapshot(
    snapshot: &BTreeMap<String, String>,
) -> Vec<(String, String)> {
    let mut attributes = Vec::new();
    let mut seen = BTreeSet::new();

    for (environment_name, resource_key) in STANDARD_RESOURCE_ENV {
        if attributes.len() >= MAX_RESOURCE_ATTRIBUTES {
            break;
        }
        let Some(value) = snapshot.get(environment_name) else {
            continue;
        };
        let value = value.trim();
        if valid_attribute_value(value) && seen.insert(resource_key.to_string()) {
            attributes.push((resource_key.to_string(), value.to_string()));
        }
    }

    if let Some(raw) = snapshot.get("OTEL_RESOURCE_ATTRIBUTES") {
        for (key, value) in resource_attribute_pairs(raw) {
            if attributes.len() >= MAX_RESOURCE_ATTRIBUTES {
                break;
            }
            if !reserved_resource_key(&key) && seen.insert(key.clone()) {
                attributes.push((key, value));
            }
        }
    }

    attributes
}

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
        let filter_text = validate_log_filter_text(filter_text)
            .map_err(|_| TelemetryError::InvalidLogFilter)?;
        let filter = EnvFilter::try_new(filter_text).map_err(|_| TelemetryError::InvalidLogFilter)?;

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

    fn resource(&self) -> Resource {
        let mut attributes = vec![
            KeyValue::new("service.name", self.identity.service_name().to_string()),
            KeyValue::new(
                "service.namespace",
                self.identity.service_namespace().to_string(),
            ),
            KeyValue::new("service.version", self.service_version.clone()),
            KeyValue::new("mcp.transport", self.identity.transport().to_string()),
        ];
        attributes.extend(
            self.resource_attributes
                .iter()
                .cloned()
                .map(|(key, value)| KeyValue::new(key, value)),
        );
        Resource::new(attributes)
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
    /// No endpoint was configured.
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
    tracer_provider: Option<TracerProvider>,
    meter_provider: Option<SdkMeterProvider>,
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
        shutdown_providers(
            self.tracer_provider.take(),
            self.meter_provider.take(),
        )
    }
}

impl fmt::Debug for TelemetryGuard {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TelemetryGuard")
            .field("status", &self.status)
            .field("tracer_provider_retained", &self.tracer_provider.is_some())
            .field("meter_provider_retained", &self.meter_provider.is_some())
            .finish()
    }
}

impl Drop for TelemetryGuard {
    fn drop(&mut self) {
        let _ = self.shutdown_inner();
    }
}

struct ProviderBundle {
    tracer_provider: Option<TracerProvider>,
    meter_provider: Option<SdkMeterProvider>,
    tracer: Option<Tracer>,
    traces: ExporterState,
    metrics: ExporterState,
}

impl ProviderBundle {
    fn disabled() -> Self {
        Self {
            tracer_provider: None,
            meter_provider: None,
            tracer: None,
            traces: ExporterState::Disabled,
            metrics: ExporterState::Disabled,
        }
    }
}

/// Installs stderr JSON logging and optional OTLP providers.
///
/// Exporter construction failures are represented only in [`TelemetryStatus`]
/// and do not prevent stderr logging. When a subscriber already exists, this
/// function leaves it and the global OpenTelemetry providers unchanged.
#[must_use]
pub fn init(config: TelemetryConfig) -> TelemetryGuard {
    let resource = config.resource();
    let mut providers = build_provider_bundle_with(
        config.endpoint.as_ref(),
        resource,
        build_tracer_provider,
        build_meter_provider,
    );

    let subscriber = install_subscriber(config.filter, providers.tracer.take());
    if subscriber == SubscriberState::Installed {
        if let Some(provider) = providers.tracer_provider.as_ref() {
            global::set_tracer_provider(provider.clone());
        }
        if let Some(provider) = providers.meter_provider.as_ref() {
            global::set_meter_provider(provider.clone());
        }

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
        let _ = shutdown_providers(
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

fn install_subscriber(filter: EnvFilter, tracer: Option<Tracer>) -> SubscriberState {
    let result = match tracer {
        Some(tracer) => tracing_subscriber::registry()
            .with(filter)
            .with(stderr_json_layer())
            .with(tracing_opentelemetry::layer().with_tracer(tracer))
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

fn stderr_json_layer<S>() -> impl tracing_subscriber::Layer<S>
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

fn build_provider_bundle_with<TraceBuilder, MeterBuilder>(
    endpoint: Option<&OtlpEndpoint>,
    resource: Resource,
    trace_builder: TraceBuilder,
    meter_builder: MeterBuilder,
) -> ProviderBundle
where
    TraceBuilder: FnOnce(&str, Resource) -> Result<(TracerProvider, Tracer), ()>,
    MeterBuilder: FnOnce(&str, Resource) -> Result<SdkMeterProvider, ()>,
{
    let Some(endpoint) = endpoint else {
        return ProviderBundle::disabled();
    };

    let (tracer_provider, tracer, traces) = match trace_builder(endpoint.as_str(), resource.clone()) {
        Ok((provider, tracer)) => (Some(provider), Some(tracer), ExporterState::Enabled),
        Err(()) => (None, None, ExporterState::BuildFailed),
    };
    let (meter_provider, metrics) = match meter_builder(endpoint.as_str(), resource) {
        Ok(provider) => (Some(provider), ExporterState::Enabled),
        Err(()) => (None, ExporterState::BuildFailed),
    };

    ProviderBundle {
        tracer_provider,
        meter_provider,
        tracer,
        traces,
        metrics,
    }
}

fn build_tracer_provider(
    endpoint: &str,
    resource: Resource,
) -> Result<(TracerProvider, Tracer), ()> {
    let exporter = opentelemetry_otlp::SpanExporter::builder()
        .with_tonic()
        .with_endpoint(endpoint)
        .with_timeout(EXPORT_TIMEOUT)
        .build()
        .map_err(|_| ())?;
    let provider = TracerProvider::builder()
        .with_batch_exporter(exporter, runtime::Tokio)
        .with_resource(resource)
        .build();
    use opentelemetry::trace::TracerProvider as _;
    let tracer = provider.tracer("ore-mcp-telemetry");
    Ok((provider, tracer))
}

fn build_meter_provider(endpoint: &str, resource: Resource) -> Result<SdkMeterProvider, ()> {
    let exporter = opentelemetry_otlp::MetricExporter::builder()
        .with_tonic()
        .with_endpoint(endpoint)
        .with_timeout(EXPORT_TIMEOUT)
        .build()
        .map_err(|_| ())?;
    let reader = PeriodicReader::builder(exporter, runtime::Tokio).build();
    Ok(SdkMeterProvider::builder()
        .with_reader(reader)
        .with_resource(resource)
        .build())
}

fn shutdown_providers(
    tracer_provider: Option<TracerProvider>,
    meter_provider: Option<SdkMeterProvider>,
) -> ShutdownStatus {
    if tracer_provider.is_none() && meter_provider.is_none() {
        return ShutdownStatus::NoExporters;
    }

    match std::thread::spawn(move || {
        let metrics_ok = meter_provider.is_none_or(|provider| provider.shutdown().is_ok());
        let traces_ok = tracer_provider.is_none_or(|provider| provider.shutdown().is_ok());
        metrics_ok && traces_ok
    })
    .join()
    {
        Ok(true) => ShutdownStatus::Flushed,
        Ok(false) => ShutdownStatus::Partial,
        Err(_) => ShutdownStatus::Panicked,
    }
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
                ("deployment.environment".to_string(), "production".to_string()),
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
    fn provider_build_failures_are_status_only_and_fail_open() {
        let endpoint = OtlpEndpoint::parse("https://collector.example:4317")
            .expect("valid endpoint");
        let resource = TelemetryConfig::new(identity(), "0.1.0", None)
            .expect("valid configuration")
            .resource();
        let bundle = build_provider_bundle_with(
            Some(&endpoint),
            resource,
            |_, _| Err::<(TracerProvider, Tracer), ()>(()),
            |_, _| Err::<SdkMeterProvider, ()>(()),
        );
        assert_eq!(bundle.traces, ExporterState::BuildFailed);
        assert_eq!(bundle.metrics, ExporterState::BuildFailed);
        assert!(bundle.tracer_provider.is_none());
        assert!(bundle.meter_provider.is_none());
        assert!(bundle.tracer.is_none());
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
}
