use opentelemetry::{global, trace::TracerProvider as _, KeyValue};
use opentelemetry_otlp::WithExportConfig;
use opentelemetry_sdk::{
    metrics::SdkMeterProvider,
    trace::{SdkTracer, SdkTracerProvider},
    Resource,
};
use tracing_opentelemetry::OpenTelemetryLayer;

use crate::endpoint::{OtlpEndpoint, EXPORT_TIMEOUT};
use crate::{ExporterState, TelemetryConfig};

pub(crate) struct ProviderBundle {
    pub tracer_provider: Option<SdkTracerProvider>,
    pub meter_provider: Option<SdkMeterProvider>,
    pub tracer: Option<SdkTracer>,
    pub traces: ExporterState,
    pub metrics: ExporterState,
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

pub(crate) fn sdk_resource(config: &TelemetryConfig) -> Resource {
    let mut attributes = vec![
        KeyValue::new("service.name", config.identity().service_name().to_string()),
        KeyValue::new(
            "service.namespace",
            config.identity().service_namespace().to_string(),
        ),
        KeyValue::new("service.version", config.service_version().to_string()),
        KeyValue::new("mcp.transport", config.identity().transport().to_string()),
    ];
    attributes.extend(
        config
            .resource_attributes()
            .iter()
            .cloned()
            .map(|(key, value)| KeyValue::new(key, value)),
    );
    Resource::builder_empty()
        .with_attributes(attributes)
        .build()
}

pub(crate) fn build_provider_bundle(config: &TelemetryConfig) -> ProviderBundle {
    build_provider_bundle_with(
        config.endpoint(),
        sdk_resource(config),
        build_tracer_provider,
        build_meter_provider,
    )
}

pub(crate) fn build_provider_bundle_with<TraceBuilder, MeterBuilder>(
    endpoint: Option<&OtlpEndpoint>,
    resource: Resource,
    trace_builder: TraceBuilder,
    meter_builder: MeterBuilder,
) -> ProviderBundle
where
    TraceBuilder: FnOnce(&str, Resource) -> Result<(SdkTracerProvider, SdkTracer), ()>,
    MeterBuilder: FnOnce(&str, Resource) -> Result<SdkMeterProvider, ()>,
{
    let Some(endpoint) = endpoint else {
        return ProviderBundle::disabled();
    };

    let (tracer_provider, tracer, traces) = match trace_builder(endpoint.as_str(), resource.clone())
    {
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

pub(crate) fn tracing_layer<S>(tracer: SdkTracer) -> OpenTelemetryLayer<S, SdkTracer>
where
    S: tracing::Subscriber + for<'lookup> tracing_subscriber::registry::LookupSpan<'lookup>,
{
    tracing_opentelemetry::layer().with_tracer(tracer)
}

pub(crate) fn install_globals(bundle: &ProviderBundle) {
    if let Some(provider) = bundle.tracer_provider.as_ref() {
        global::set_tracer_provider(provider.clone());
    }
    if let Some(provider) = bundle.meter_provider.as_ref() {
        global::set_meter_provider(provider.clone());
    }
}

pub(crate) fn shutdown_providers(
    tracer_provider: Option<SdkTracerProvider>,
    meter_provider: Option<SdkMeterProvider>,
) -> crate::ShutdownStatus {
    if tracer_provider.is_none() && meter_provider.is_none() {
        return crate::ShutdownStatus::NoExporters;
    }

    match std::thread::spawn(move || {
        let metrics_ok = meter_provider.is_none_or(|provider| provider.shutdown().is_ok());
        let traces_ok = tracer_provider.is_none_or(|provider| provider.shutdown().is_ok());
        metrics_ok && traces_ok
    })
    .join()
    {
        Ok(true) => crate::ShutdownStatus::Flushed,
        Ok(false) => crate::ShutdownStatus::Partial,
        Err(_) => crate::ShutdownStatus::Panicked,
    }
}

pub(crate) fn build_tracer_provider(
    endpoint: &str,
    resource: Resource,
) -> Result<(SdkTracerProvider, SdkTracer), ()> {
    if tokio::runtime::Handle::try_current().is_err() {
        return Err(());
    }

    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let exporter = opentelemetry_otlp::SpanExporter::builder()
            .with_tonic()
            .with_endpoint(endpoint)
            .with_timeout(EXPORT_TIMEOUT)
            .build()
            .map_err(|_| ())?;
        let provider = SdkTracerProvider::builder()
            .with_batch_exporter(exporter)
            .with_resource(resource)
            .build();
        let tracer = provider.tracer("ore-mcp-telemetry");
        Ok((provider, tracer))
    }))
    .unwrap_or(Err(()))
}

pub(crate) fn build_meter_provider(
    endpoint: &str,
    resource: Resource,
) -> Result<SdkMeterProvider, ()> {
    if tokio::runtime::Handle::try_current().is_err() {
        return Err(());
    }

    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let exporter = opentelemetry_otlp::MetricExporter::builder()
            .with_tonic()
            .with_endpoint(endpoint)
            .with_timeout(EXPORT_TIMEOUT)
            .build()
            .map_err(|_| ())?;
        Ok(SdkMeterProvider::builder()
            .with_periodic_exporter(exporter)
            .with_resource(resource)
            .build())
    }))
    .unwrap_or(Err(()))
}
