//! Hardened, read-only organization MCP server shared by the fleet.
//!
//! Product-specific servers remain free to expose richer diagnostics. This
//! crate supplies the minimum safe server every GitHub organization can deploy:
//! fleet identity, Zed dependency provenance, `ores-otel` telemetry status,
//! Shared Auth boundary guidance, encrypted-environment policy, and the common
//! security contract. It deliberately exposes no mutation or credential-taking
//! tool.

#![forbid(unsafe_code)]

use std::io;

use ore_mcp_bootstrap::runtime::ServerIdentity;
use ore_mcp_zed_graph::DependencyGraph;
use ores_mcp_server_core_libs::observability::{
    self, TelemetryStatus, ToolClass, ToolMetrics, ToolOutcome,
};
use rmcp::{
    handler::server::router::tool::ToolRouter,
    model::{Implementation, ServerCapabilities, ServerInfo},
    tool, tool_handler, tool_router,
    transport::stdio,
    ServerHandler, ServiceExt,
};
use serde_json::{json, Value};
use tracing::Instrument;

const MAX_TOOL_OUTPUT_BYTES: usize = 64 * 1024;
const ORES_OTEL_REVISION: &str = "e559a76f869c2c2d9bf939b510d358a3924abd81";

/// Compile-time identity and dependency policy for one organization server.
#[derive(Clone, Copy, Debug)]
pub struct OrgSpec {
    /// GitHub organization login and telemetry namespace.
    pub organization: &'static str,
    /// Canonical `owner/name` repository coordinate.
    pub repository: &'static str,
    /// Server process and MCP implementation name.
    pub service_name: &'static str,
    /// Zed package identity.
    pub package_name: &'static str,
    /// Canonical Zed dependency coordinates.
    pub dependencies: &'static [&'static str],
    /// Package version included in MCP and telemetry identity.
    pub version: &'static str,
}

/// Read-only organization server with closed, no-argument tools.
#[derive(Clone)]
pub struct OrgMcpServer {
    spec: OrgSpec,
    dependency_graph: DependencyGraph,
    telemetry: TelemetrySnapshot,
    metrics: ToolMetrics,
    tool_router: ToolRouter<Self>,
}

#[derive(Clone, Copy)]
struct TelemetrySnapshot {
    subscriber_installed: bool,
    trace_exporter: bool,
    metric_exporter: bool,
    log_exporter: bool,
}

impl From<TelemetryStatus> for TelemetrySnapshot {
    fn from(status: TelemetryStatus) -> Self {
        Self {
            subscriber_installed: status.subscriber_installed(),
            trace_exporter: status.trace_exporter(),
            metric_exporter: status.metric_exporter(),
            log_exporter: status.log_exporter(),
        }
    }
}

impl OrgMcpServer {
    fn new(spec: OrgSpec, telemetry: TelemetryStatus) -> io::Result<Self> {
        let dependency_graph = validate_spec(spec)?;
        Ok(Self {
            spec,
            dependency_graph,
            telemetry: telemetry.into(),
            metrics: ToolMetrics::global(),
            tool_router: Self::tool_router(),
        })
    }

    fn successful_json(&self, class: ToolClass, value: Value) -> Result<String, String> {
        let timer = self.metrics.start(class);
        let rendered = serde_json::to_string_pretty(&value)
            .map_err(|_| "failed to render bounded server result".to_string())?;
        if rendered.len() > MAX_TOOL_OUTPUT_BYTES {
            timer.finish(ToolOutcome::Error);
            return Err("server result exceeded the fixed output bound".to_string());
        }
        timer.finish(ToolOutcome::Ok);
        Ok(rendered)
    }
}

fn validate_spec(spec: OrgSpec) -> io::Result<DependencyGraph> {
    ServerIdentity::stdio(spec.service_name, spec.organization)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
    DependencyGraph::new(
        spec.organization,
        spec.repository,
        spec.package_name,
        spec.dependencies.iter().copied(),
    )
    .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))
}

#[tool_router]
impl OrgMcpServer {
    /// Return the canonical organization, repository, package, and access mode.
    #[tool(
        description = "Return the immutable organization-server identity and read-only access contract."
    )]
    fn org_identity(&self) -> Result<String, String> {
        self.successful_json(
            ToolClass::Inventory,
            json!({
                "organization": self.spec.organization,
                "repository": self.spec.repository,
                "service": self.spec.service_name,
                "package": self.spec.package_name,
                "version": self.spec.version,
                "transport": "stdio",
                "accessMode": "read_only",
            }),
        )
    }

    /// Return the closed Zed package graph and materialization contract.
    #[tool(
        description = "Return the canonical Zed dependency graph, immutable package coordinates, and .vendor/.zed materialization policy."
    )]
    fn zed_dependency_graph(&self) -> Result<String, String> {
        self.successful_json(
            ToolClass::Inventory,
            self.dependency_graph.structured_content(),
        )
    }

    /// Return non-sensitive logging and OpenTelemetry initialization status.
    #[tool(
        description = "Return non-sensitive ores-otel logging, traces, metrics, and logs initialization status without collector details."
    )]
    fn telemetry_status(&self) -> Result<String, String> {
        self.successful_json(
            ToolClass::Health,
            json!({
                "implementation": "ores-otel/ores-mcp-server-core-libs.rs",
                "revision": ORES_OTEL_REVISION,
                "stdoutReservedForMcp": true,
                "stderrJsonLogging": true,
                "subscriberInstalled": self.telemetry.subscriber_installed,
                "exporters": {
                    "traces": self.telemetry.trace_exporter,
                    "metrics": self.telemetry.metric_exporter,
                    "logs": self.telemetry.log_exporter,
                },
                "attributes": "bounded_low_cardinality_no_credentials_or_payloads",
            }),
        )
    }

    /// Return the Shared Auth integration boundary for product extensions.
    #[tool(
        description = "Describe the fail-closed Shared Auth boundary and whether a public authority URL is configured; never accepts or inspects credentials."
    )]
    fn shared_auth_policy(&self) -> Result<String, String> {
        self.successful_json(
            ToolClass::Health,
            json!({
                "configured": std::env::var_os("SHARED_AUTH_BASE_URL").is_some(),
                "authority": "shared-auth",
                "ordinaryVerification": "local_ES256_JWKS_exact_issuer_audience_client_realm",
                "immediateRevocation": "protected_server_to_server_introspection_only",
                "productAuthorization": "owning_product_database_and_policy",
                "realms": "admin_and_customer_are_independent",
                "outcomes": ["anonymous", "unauthenticated", "degraded", "authenticated"],
                "credentialsAcceptedByThisTool": false,
            }),
        )
    }

    /// Return the SOPS, age, Just, and Nix environment-file policy.
    #[tool(
        description = "Return the encrypted-environment contract: SOPS+age ciphertext in env/enc, plaintext only in ignored env/dec, and Just+Nix execution."
    )]
    fn environment_policy(&self) -> Result<String, String> {
        self.successful_json(
            ToolClass::Details,
            json!({
                "encryptedGlob": "env/enc/*.env.enc",
                "decryptedGlob": "env/dec/*.env",
                "cipher": "sops_age",
                "taskRunner": "just",
                "toolchain": "nix",
                "plaintextTracked": false,
                "privateAgeIdentityTracked": false,
                "secretValuesLogged": false,
            }),
        )
    }

    /// Return the minimum security guarantees inherited by the fleet server.
    #[tool(
        description = "Return the common read-only, bounded-output, redaction, transport, telemetry, auth, and dependency-management guarantees."
    )]
    fn security_baseline(&self) -> Result<String, String> {
        self.successful_json(
            ToolClass::Details,
            json!({
                "mutations": "none",
                "toolInputs": "closed_no_argument_schemas",
                "toolOutputBytesMax": MAX_TOOL_OUTPUT_BYTES,
                "protocolStdoutOnly": true,
                "logs": "structured_json_stderr",
                "telemetry": "ores-otel_bounded_low_cardinality",
                "authentication": "shared-auth_when_a_product_boundary_requires_it",
                "authorization": "product_local_never_inferred_from_identity",
                "dependencyManagement": "zed-pkg_with_immutable_git_revisions",
                "secrets": "sops_age_env_injection_never_cli_flags_or_logs",
            }),
        )
    }
}

#[tool_handler(router = self.tool_router)]
impl ServerHandler for OrgMcpServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::new(
                self.spec.service_name,
                self.spec.version,
            ))
            .with_instructions(format!(
                "Read-only organization diagnostics for {}. Start with org_identity; use \
                 zed_dependency_graph, telemetry_status, shared_auth_policy, \
                 environment_policy, and security_baseline for the inherited fleet contracts.",
                self.spec.organization
            ))
    }
}

/// Initialize `ores-otel` and serve one organization server over MCP stdio.
///
/// # Errors
///
/// Returns an error when identity/dependency validation, MCP initialization,
/// transport operation, or shutdown waiting fails.
pub async fn run_stdio(spec: OrgSpec) -> Result<(), Box<dyn std::error::Error>> {
    validate_spec(spec)?;
    let telemetry_guard = observability::init(spec.service_name, spec.organization);
    let server = OrgMcpServer::new(spec, telemetry_guard.status())?;
    tracing::info!(
        service.name = spec.service_name,
        service.namespace = spec.organization,
        service.version = spec.version,
        transport = "stdio",
        access.mode = "read_only",
        "starting organization MCP server"
    );
    let server_span = tracing::info_span!(
        "mcp.server",
        rpc.system = "mcp",
        transport = "stdio",
        access.mode = "read_only"
    );
    let service = server
        .serve(stdio())
        .instrument(server_span.clone())
        .await?;
    service.waiting().instrument(server_span).await?;
    drop(telemetry_guard);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const DEPENDENCIES: &[&str] = &[
        "ores-otel/ores-mcp-server-core-libs.rs",
        "shared-auth/shared-auth-clients",
        "zed-pkg/zed-cli",
    ];

    fn spec() -> OrgSpec {
        OrgSpec {
            organization: "example-org",
            repository: "example-org/example-mcp-server.rs",
            service_name: "example-mcp-server",
            package_name: "example-mcp-server",
            dependencies: DEPENDENCIES,
            version: "0.1.0",
        }
    }

    #[test]
    fn validated_spec_requires_same_org_repository_and_zed_dependencies() {
        let graph = validate_spec(spec()).expect("valid fleet spec");
        assert_eq!(graph.organization(), "example-org");
        assert_eq!(graph.dependencies(), DEPENDENCIES);

        let invalid = OrgSpec {
            repository: "different-org/example-mcp-server.rs",
            ..spec()
        };
        assert!(validate_spec(invalid).is_err());
    }

    #[test]
    fn all_public_tools_are_closed_no_argument_tools() {
        let router = OrgMcpServer::tool_router();
        let names = router
            .list_all()
            .into_iter()
            .map(|tool| tool.name.to_string())
            .collect::<Vec<_>>();
        assert_eq!(names.len(), 6);
        for name in [
            "org_identity",
            "zed_dependency_graph",
            "telemetry_status",
            "shared_auth_policy",
            "environment_policy",
            "security_baseline",
        ] {
            assert!(names.iter().any(|candidate| candidate == name));
        }
    }
}
