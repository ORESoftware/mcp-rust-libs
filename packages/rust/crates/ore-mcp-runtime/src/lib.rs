//! Ordered, stdout-safe lifecycle helpers for Rust MCP servers.
//!
//! The crate owns only generic lifecycle concerns: bootstrap ordering,
//! low-cardinality runtime metadata, official `rmcp` stdio startup and
//! shutdown, and optional exact protocol-version enforcement. Product handlers,
//! authorization, tool schemas, configuration parsing, telemetry provider
//! construction, and repository-specific hooks remain in their owning server
//! crates.
//!
//! MCP owns stdout. This crate never prints, and callers must install a
//! stderr-only tracing subscriber before serving a stdio transport.

#![forbid(unsafe_code)]

use std::{error::Error, fmt};

pub use ore_mcp_bootstrap::runtime::{IdentityError, STDIO_TRANSPORT, ServerIdentity};
#[cfg(feature = "rmcp-stdio")]
use rmcp::{
    ErrorData as McpError, RoleServer, ServiceExt,
    model::{ClientNotification, ClientRequest, ProtocolVersion, ServerInfo, ServerResult},
    service::{NotificationContext, RequestContext, Service},
    transport::stdio,
};
#[cfg(feature = "rmcp-stdio")]
use tracing::Instrument;

/// A boxed startup or runtime error propagated without logging its contents.
pub type RuntimeError = Box<dyn Error + Send + Sync + 'static>;

/// The server's externally visible authorization posture.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AccessMode {
    /// The server exposes observation and diagnostics only.
    ReadOnly,
    /// The server exposes one or more state-changing operations.
    MutationCapable,
}

impl AccessMode {
    /// Returns the stable low-cardinality telemetry label for this mode.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ReadOnly => "read_only",
            Self::MutationCapable => "mutation_capable",
        }
    }
}

impl fmt::Display for AccessMode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Validated metadata attached to one stdio server lifecycle.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeSpec {
    identity: ServerIdentity,
    service_version: String,
    access_mode: AccessMode,
}

impl RuntimeSpec {
    /// Creates a validated stdio specification from service components.
    ///
    /// # Errors
    ///
    /// Returns a value-free error when identity or version metadata is not a
    /// bounded portable token.
    pub fn stdio(
        service_name: impl Into<String>,
        service_namespace: impl Into<String>,
        service_version: impl Into<String>,
        access_mode: AccessMode,
    ) -> Result<Self, RuntimeSpecError> {
        let identity = ServerIdentity::stdio(service_name, service_namespace)?;
        Self::new(identity, service_version, access_mode)
    }

    /// Creates a stdio specification from an already validated identity.
    ///
    /// # Errors
    ///
    /// Returns [`RuntimeSpecError::UnsupportedTransport`] when the identity is
    /// not for stdio, or [`RuntimeSpecError::InvalidServiceVersion`] when the
    /// version is empty, oversized, or not a portable release token.
    pub fn new(
        identity: ServerIdentity,
        service_version: impl Into<String>,
        access_mode: AccessMode,
    ) -> Result<Self, RuntimeSpecError> {
        if identity.transport() != STDIO_TRANSPORT {
            return Err(RuntimeSpecError::UnsupportedTransport);
        }
        let service_version = service_version.into();
        if !valid_service_version(&service_version) {
            return Err(RuntimeSpecError::InvalidServiceVersion);
        }
        Ok(Self {
            identity,
            service_version,
            access_mode,
        })
    }

    /// Returns the validated service identity owned by `ore-mcp-bootstrap`.
    #[must_use]
    pub const fn identity(&self) -> &ServerIdentity {
        &self.identity
    }

    /// Returns the bounded service version.
    #[must_use]
    pub fn service_version(&self) -> &str {
        &self.service_version
    }

    /// Returns the declared authorization posture.
    #[must_use]
    pub const fn access_mode(&self) -> AccessMode {
        self.access_mode
    }

    /// Returns stable, low-cardinality lifecycle attributes.
    #[must_use]
    pub fn startup_attributes(&self) -> [(&'static str, &str); 5] {
        [
            ("service.name", self.identity.service_name()),
            ("service.namespace", self.identity.service_namespace()),
            ("service.version", self.service_version()),
            ("transport", self.identity.transport()),
            ("access.mode", self.access_mode.as_str()),
        ]
    }
}

fn valid_service_version(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_' | b'+'))
}

/// A value-free runtime specification validation failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeSpecError {
    /// The shared bootstrap crate rejected service identity metadata.
    Identity(IdentityError),
    /// A non-stdio identity was supplied to the stdio runtime.
    UnsupportedTransport,
    /// The service version was not a bounded portable token.
    InvalidServiceVersion,
}

impl fmt::Display for RuntimeSpecError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Identity(_) => formatter.write_str("invalid MCP service identity"),
            Self::UnsupportedTransport => {
                formatter.write_str("ore-mcp-runtime currently supports stdio only")
            }
            Self::InvalidServiceVersion => formatter.write_str("invalid MCP service version"),
        }
    }
}

impl Error for RuntimeSpecError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Identity(error) => Some(error),
            Self::UnsupportedTransport | Self::InvalidServiceVersion => None,
        }
    }
}

impl From<IdentityError> for RuntimeSpecError {
    fn from(error: IdentityError) -> Self {
        Self::Identity(error)
    }
}

/// Ordered phases for a safe MCP server bootstrap.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BootstrapPhase {
    /// Parse and validate non-secret operational configuration.
    ParseOperationalConfig,
    /// Install stderr-only and optional OTLP telemetry.
    InitializeTelemetry,
    /// Construct the product-owned handler and authorization policy.
    ConstructServer,
    /// Apply product-owned router or metadata hooks.
    ApplyProductHooks,
    /// Start the selected MCP transport.
    ServeTransport,
    /// Wait for protocol or process shutdown.
    WaitForShutdown,
    /// Flush caller-owned telemetry providers by dropping their guard.
    FlushTelemetry,
}

/// Canonical bootstrap ordering used by architecture tests and templates.
pub const REQUIRED_BOOTSTRAP_ORDER: &[BootstrapPhase] = &[
    BootstrapPhase::ParseOperationalConfig,
    BootstrapPhase::InitializeTelemetry,
    BootstrapPhase::ConstructServer,
    BootstrapPhase::ApplyProductHooks,
    BootstrapPhase::ServeTransport,
    BootstrapPhase::WaitForShutdown,
    BootstrapPhase::FlushTelemetry,
];

/// A service wrapper that rejects initialize requests for every protocol
/// version except one exact version.
///
/// This is intentionally a service-level adapter rather than a handler hook.
/// `rmcp` 2.2 reapplies protocol negotiation after the handler returns, so a
/// handler's `ServerInfo.protocol_version` alone is not a version ceiling.
#[cfg(feature = "rmcp-stdio")]
#[derive(Clone, Debug)]
pub struct ExactProtocol<S> {
    inner: S,
    protocol_version: ProtocolVersion,
}

#[cfg(feature = "rmcp-stdio")]
impl<S> ExactProtocol<S> {
    /// Wraps a service with an exact initialize-version requirement.
    #[must_use]
    pub fn new(inner: S, protocol_version: ProtocolVersion) -> Self {
        Self {
            inner,
            protocol_version,
        }
    }

    /// Returns whether a requested version is accepted.
    #[must_use]
    pub fn accepts(&self, requested: &ProtocolVersion) -> bool {
        requested == &self.protocol_version
    }

    /// Returns the exact accepted protocol version.
    #[must_use]
    pub const fn protocol_version(&self) -> &ProtocolVersion {
        &self.protocol_version
    }

    /// Returns the wrapped service.
    #[must_use]
    pub const fn inner(&self) -> &S {
        &self.inner
    }

    /// Consumes the wrapper and returns the service.
    #[must_use]
    pub fn into_inner(self) -> S {
        self.inner
    }
}

#[cfg(feature = "rmcp-stdio")]
impl<S> Service<RoleServer> for ExactProtocol<S>
where
    S: Service<RoleServer>,
{
    async fn handle_request(
        &self,
        request: ClientRequest,
        context: RequestContext<RoleServer>,
    ) -> Result<ServerResult, McpError> {
        if let ClientRequest::InitializeRequest(initialize) = &request {
            if !self.accepts(&initialize.params.protocol_version) {
                return Err(McpError::invalid_request(
                    "unsupported MCP protocol version",
                    None,
                ));
            }
        }
        self.inner.handle_request(request, context).await
    }

    async fn handle_notification(
        &self,
        notification: ClientNotification,
        context: NotificationContext<RoleServer>,
    ) -> Result<(), McpError> {
        self.inner.handle_notification(notification, context).await
    }

    fn get_info(&self) -> ServerInfo {
        let mut info = self.inner.get_info();
        info.protocol_version = self.protocol_version.clone();
        info
    }
}

/// A configured server that retains its telemetry guard until shutdown.
pub struct PreparedStdio<G, S> {
    telemetry_guard: G,
    server: S,
    spec: RuntimeSpec,
}

impl<G, S> PreparedStdio<G, S> {
    /// Returns the validated runtime metadata.
    #[must_use]
    pub const fn spec(&self) -> &RuntimeSpec {
        &self.spec
    }

    /// Returns the product-owned server.
    #[must_use]
    pub const fn server(&self) -> &S {
        &self.server
    }

    /// Returns the product-owned server for a local pre-serve hook.
    ///
    /// This supports repository-specific router or metadata normalization
    /// without moving that policy into the shared runtime crate.
    #[must_use]
    pub fn server_mut(&mut self) -> &mut S {
        &mut self.server
    }

    /// Consumes the prepared server without starting a transport.
    #[must_use]
    pub fn into_parts(self) -> (G, S, RuntimeSpec) {
        (self.telemetry_guard, self.server, self.spec)
    }

    /// Serves the prepared service over stdin and stdout until shutdown.
    ///
    /// The telemetry guard remains alive for the complete protocol lifetime and
    /// is dropped only after the service stops or returns an error.
    ///
    /// # Errors
    ///
    /// Returns an error when MCP initialization, transport operation, or
    /// shutdown waiting fails.
    #[cfg(feature = "rmcp-stdio")]
    pub async fn serve(self) -> Result<(), RuntimeError>
    where
        S: Service<RoleServer>,
    {
        let Self {
            telemetry_guard,
            server,
            spec,
        } = self;
        let _telemetry_guard = telemetry_guard;
        serve_stdio(server, spec).await
    }
}

/// Runs configuration, telemetry, and server construction in the required
/// order while retaining the telemetry guard for the eventual service lifetime.
///
/// Product-owned hooks can be applied through [`PreparedStdio::server_mut`]
/// before calling [`PreparedStdio::serve`]. Callback errors are propagated
/// without being logged by this crate.
///
/// # Errors
///
/// Returns the first callback error. If server construction fails, the already
/// initialized telemetry guard is dropped before the error is returned.
pub fn prepare_stdio<C, G, S, P, T, B>(
    spec: RuntimeSpec,
    parse_config: P,
    initialize_telemetry: T,
    build_server: B,
) -> Result<PreparedStdio<G, S>, RuntimeError>
where
    P: FnOnce() -> Result<C, RuntimeError>,
    T: FnOnce(&C, &RuntimeSpec) -> Result<G, RuntimeError>,
    B: FnOnce(&C, &RuntimeSpec) -> Result<S, RuntimeError>,
{
    let config = parse_config()?;
    let telemetry_guard = initialize_telemetry(&config, &spec)?;
    let server = build_server(&config, &spec)?;
    Ok(PreparedStdio {
        telemetry_guard,
        server,
        spec,
    })
}

/// Runs the complete ordered stdio lifecycle with caller-owned callbacks.
///
/// Configuration is parsed before telemetry initialization, telemetry is
/// initialized before product construction, and its guard remains alive until
/// the protocol service stops.
///
/// # Errors
///
/// Returns the first callback, MCP initialization, transport, or shutdown error.
#[cfg(feature = "rmcp-stdio")]
pub async fn run_stdio<C, G, S, P, T, B>(
    spec: RuntimeSpec,
    parse_config: P,
    initialize_telemetry: T,
    build_server: B,
) -> Result<(), RuntimeError>
where
    S: Service<RoleServer>,
    P: FnOnce() -> Result<C, RuntimeError>,
    T: FnOnce(&C, &RuntimeSpec) -> Result<G, RuntimeError>,
    B: FnOnce(&C, &RuntimeSpec) -> Result<S, RuntimeError>,
{
    prepare_stdio(spec, parse_config, initialize_telemetry, build_server)?
        .serve()
        .await
}

/// Serves an already constructed MCP service over stdin and stdout.
///
/// Existing `ServerHandler` values remain compatible through `rmcp`'s blanket
/// `Service<RoleServer>` implementation. Service-level adapters such as
/// [`ExactProtocol`] can now be composed before serving.
///
/// Callers that need ordering and telemetry-guard retention should prefer
/// [`prepare_stdio`] or [`run_stdio`].
///
/// # Errors
///
/// Returns an error when MCP initialization, transport operation, or shutdown
/// waiting fails.
#[cfg(feature = "rmcp-stdio")]
pub async fn serve_stdio<S>(server: S, spec: RuntimeSpec) -> Result<(), RuntimeError>
where
    S: Service<RoleServer>,
{
    tracing::info!(
        service.name = spec.identity.service_name(),
        service.namespace = spec.identity.service_namespace(),
        service.version = spec.service_version.as_str(),
        transport = spec.identity.transport(),
        access.mode = spec.access_mode.as_str(),
        "starting MCP server"
    );
    let server_span = server_span(&spec);
    let service = server
        .serve(stdio())
        .instrument(server_span.clone())
        .await?;
    service.waiting().instrument(server_span).await?;
    Ok(())
}

/// Builds the standard stdio lifecycle span from validated metadata.
#[cfg(feature = "rmcp-stdio")]
#[must_use]
pub fn server_span(spec: &RuntimeSpec) -> tracing::Span {
    tracing::info_span!(
        "mcp.server",
        rpc.system = "mcp",
        transport = spec.identity.transport(),
        service.name = spec.identity.service_name(),
        service.namespace = spec.identity.service_namespace(),
        service.version = spec.service_version.as_str(),
        access.mode = spec.access_mode.as_str(),
    )
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use super::*;

    #[derive(Clone)]
    struct DropMarker(Arc<Mutex<Vec<&'static str>>>);

    impl Drop for DropMarker {
        fn drop(&mut self) {
            self.0.lock().expect("event lock").push("drop");
        }
    }

    fn test_spec() -> RuntimeSpec {
        RuntimeSpec::stdio(
            "example-mcp-server",
            "example",
            "1.0.0+test",
            AccessMode::ReadOnly,
        )
        .expect("valid runtime spec")
    }

    #[test]
    fn access_mode_labels_are_stable() {
        assert_eq!(AccessMode::ReadOnly.as_str(), "read_only");
        assert_eq!(AccessMode::MutationCapable.as_str(), "mutation_capable");
    }

    #[test]
    fn runtime_spec_delegates_identity_and_validates_version() {
        let spec = test_spec();
        assert_eq!(spec.identity().service_name(), "example-mcp-server");
        assert_eq!(spec.identity().service_namespace(), "example");
        assert_eq!(spec.identity().transport(), STDIO_TRANSPORT);
        assert_eq!(spec.service_version(), "1.0.0+test");
        assert_eq!(spec.access_mode(), AccessMode::ReadOnly);

        assert!(RuntimeSpec::stdio("bad\nname", "example", "1", AccessMode::ReadOnly).is_err());
        assert!(RuntimeSpec::stdio("good", "example", "", AccessMode::ReadOnly).is_err());
        assert!(
            RuntimeSpec::stdio("good", "example", "1.0 release", AccessMode::ReadOnly).is_err()
        );
        assert!(RuntimeSpec::stdio("good", "example", "1/0", AccessMode::ReadOnly).is_err());
    }

    #[test]
    fn stdio_runtime_rejects_other_transport_identity() {
        let identity = ServerIdentity::new("example", "org", "http").expect("valid identity");
        assert_eq!(
            RuntimeSpec::new(identity, "1.0.0", AccessMode::ReadOnly),
            Err(RuntimeSpecError::UnsupportedTransport)
        );
    }

    #[test]
    fn bootstrap_order_is_explicit_and_stable() {
        assert_eq!(
            REQUIRED_BOOTSTRAP_ORDER,
            &[
                BootstrapPhase::ParseOperationalConfig,
                BootstrapPhase::InitializeTelemetry,
                BootstrapPhase::ConstructServer,
                BootstrapPhase::ApplyProductHooks,
                BootstrapPhase::ServeTransport,
                BootstrapPhase::WaitForShutdown,
                BootstrapPhase::FlushTelemetry,
            ]
        );
    }

    #[cfg(feature = "rmcp-stdio")]
    #[test]
    fn exact_protocol_accepts_only_the_configured_version() {
        let wrapper = ExactProtocol::new(41_u8, ProtocolVersion::V_2025_11_25);
        assert!(wrapper.accepts(&ProtocolVersion::V_2025_11_25));
        assert!(!wrapper.accepts(&ProtocolVersion::V_2026_07_28));
        assert!(!wrapper.accepts(&ProtocolVersion::V_2025_06_18));
        assert_eq!(wrapper.protocol_version(), &ProtocolVersion::V_2025_11_25);
        assert_eq!(wrapper.inner(), &41);
        assert_eq!(wrapper.into_inner(), 41);
    }

    #[test]
    fn prepare_orders_callbacks_and_retains_guard() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let config_events = Arc::clone(&events);
        let telemetry_events = Arc::clone(&events);
        let server_events = Arc::clone(&events);
        let guard_events = Arc::clone(&events);

        let prepared = prepare_stdio(
            test_spec(),
            move || {
                config_events.lock().expect("event lock").push("config");
                Ok::<_, RuntimeError>(41_u8)
            },
            move |config, _spec| {
                assert_eq!(*config, 41);
                telemetry_events
                    .lock()
                    .expect("event lock")
                    .push("telemetry");
                Ok::<_, RuntimeError>(DropMarker(guard_events))
            },
            move |config, spec| {
                assert_eq!(*config, 41);
                assert_eq!(spec.service_version(), "1.0.0+test");
                server_events.lock().expect("event lock").push("server");
                Ok::<_, RuntimeError>("handler")
            },
        )
        .expect("prepare server");

        assert_eq!(
            events.lock().expect("event lock").as_slice(),
            ["config", "telemetry", "server"]
        );
        assert_eq!(prepared.server(), &"handler");
        drop(prepared);
        assert_eq!(
            events.lock().expect("event lock").as_slice(),
            ["config", "telemetry", "server", "drop"]
        );
    }

    #[test]
    fn construction_error_drops_initialized_telemetry() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let config_events = Arc::clone(&events);
        let telemetry_events = Arc::clone(&events);
        let server_events = Arc::clone(&events);
        let guard_events = Arc::clone(&events);

        let result: Result<PreparedStdio<DropMarker, ()>, RuntimeError> = prepare_stdio(
            test_spec(),
            move || {
                config_events.lock().expect("event lock").push("config");
                Ok::<_, RuntimeError>(())
            },
            move |_config, _spec| {
                telemetry_events
                    .lock()
                    .expect("event lock")
                    .push("telemetry");
                Ok::<_, RuntimeError>(DropMarker(guard_events))
            },
            move |_config, _spec| {
                server_events.lock().expect("event lock").push("server");
                Err(std::io::Error::other("construction failed").into())
            },
        );

        assert!(result.is_err());
        assert_eq!(
            events.lock().expect("event lock").as_slice(),
            ["config", "telemetry", "server", "drop"]
        );
    }
}
