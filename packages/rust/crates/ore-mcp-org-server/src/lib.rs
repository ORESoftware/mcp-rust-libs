//! Hardened, read-only organization MCP server shared by the fleet.
//!
//! Product-specific servers remain free to expose richer diagnostics. This
//! crate supplies the minimum safe server every GitHub organization can deploy:
//! fleet identity, Zed dependency provenance, `ores-otel` telemetry status,
//! Shared Auth boundary guidance, encrypted-environment policy, the common
//! security contract, and exact-scope provider posture for GitHub, AWS, GCP,
//! Supabase, Neon, Cloudflare, Kubernetes, and NATS. It deliberately exposes no
//! mutation or credential-taking tool.

#![forbid(unsafe_code)]

mod catalog;
mod providers;
mod remote;

use std::io;
use std::pin::Pin;
use std::task::{ready, Context, Poll};

use ore_mcp_bootstrap::runtime::ServerIdentity;
use ore_mcp_runtime::ExactProtocol;
use ore_mcp_zed_graph::DependencyGraph;
use ores_mcp_server_core_libs::observability::{
    self, TelemetryStatus, ToolClass, ToolMetrics, ToolOutcome,
};
use rmcp::{
    handler::server::router::tool::ToolRouter,
    handler::server::wrapper::Parameters,
    model::{
        GetPromptRequestParams, GetPromptResult, Implementation, ListPromptsResult,
        ListResourcesResult, PaginatedRequestParams, Prompt, PromptMessage, ProtocolVersion,
        ReadResourceRequestParams, ReadResourceResult, Resource, ResourceContents, Role,
        ServerCapabilities, ServerInfo,
    },
    service::RequestContext,
    tool, tool_handler, tool_router,
    transport::stdio,
    ErrorData, RoleServer, ServerHandler, ServiceExt,
};
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::{json, Value};
use tokio::io::{AsyncBufRead, AsyncRead, BufReader, ReadBuf};
use tracing::Instrument;

use providers::{ProviderContext, ProviderReport};

pub use remote::run_http;

/// Maximum accepted JSON-RPC request frame on stdio.
pub const MAX_STDIO_FRAME_BYTES: usize = 1024 * 1024;
const MAX_TOOL_OUTPUT_BYTES: usize = 512 * 1024;
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
    providers: ProviderContext,
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

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct NoArguments {}

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
    fn new(
        spec: OrgSpec,
        telemetry: TelemetryStatus,
        providers: ProviderContext,
    ) -> io::Result<Self> {
        let dependency_graph = validate_spec(spec)?;
        Ok(Self {
            spec,
            dependency_graph,
            providers,
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

    fn provider_json(&self, report: ProviderReport) -> Result<String, String> {
        let value = serde_json::to_value(report)
            .map_err(|_| "failed to render bounded provider result".to_owned())?;
        self.successful_json(ToolClass::Health, value)
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
    #[tracing::instrument(name = "mcp.tool", skip_all, fields(mcp.tool.name = "org_identity", mcp.tool.class = "inventory"))]
    fn org_identity(&self, Parameters(_): Parameters<NoArguments>) -> Result<String, String> {
        self.successful_json(
            ToolClass::Inventory,
            json!({
                "organization": self.spec.organization,
                "repository": self.spec.repository,
                "service": self.spec.service_name,
                "package": self.spec.package_name,
                "version": self.spec.version,
                "protocol": "2025-11-25",
                "transports": ["stdio", "streamable_http"],
                "clients": ["cursor", "openai_chatgpt", "anthropic_claude", "gemini", "grok", "qwen"],
                "accessMode": "read_only",
            }),
        )
    }

    /// Return the closed Zed package graph and materialization contract.
    #[tool(
        description = "Return the canonical Zed dependency graph, immutable package coordinates, and .vendor/.zed materialization policy."
    )]
    #[tracing::instrument(name = "mcp.tool", skip_all, fields(mcp.tool.name = "zed_dependency_graph", mcp.tool.class = "inventory"))]
    fn zed_dependency_graph(
        &self,
        Parameters(_): Parameters<NoArguments>,
    ) -> Result<String, String> {
        self.successful_json(
            ToolClass::Inventory,
            self.dependency_graph.structured_content(),
        )
    }

    /// Return non-sensitive logging and OpenTelemetry initialization status.
    #[tool(
        description = "Return non-sensitive ores-otel logging, traces, metrics, and logs initialization status without collector details."
    )]
    #[tracing::instrument(name = "mcp.tool", skip_all, fields(mcp.tool.name = "telemetry_status", mcp.tool.class = "health"))]
    fn telemetry_status(&self, Parameters(_): Parameters<NoArguments>) -> Result<String, String> {
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
    #[tracing::instrument(name = "mcp.tool", skip_all, fields(mcp.tool.name = "shared_auth_policy", mcp.tool.class = "health"))]
    fn shared_auth_policy(&self, Parameters(_): Parameters<NoArguments>) -> Result<String, String> {
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
    #[tracing::instrument(name = "mcp.tool", skip_all, fields(mcp.tool.name = "environment_policy", mcp.tool.class = "details"))]
    fn environment_policy(&self, Parameters(_): Parameters<NoArguments>) -> Result<String, String> {
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
    #[tracing::instrument(name = "mcp.tool", skip_all, fields(mcp.tool.name = "security_baseline", mcp.tool.class = "details"))]
    fn security_baseline(&self, Parameters(_): Parameters<NoArguments>) -> Result<String, String> {
        self.successful_json(
            ToolClass::Details,
            json!({
                "mutations": "none",
                "toolInputs": "closed_no_argument_schemas",
                "toolOutputBytesMax": MAX_TOOL_OUTPUT_BYTES,
                "protocolStdoutOnly": true,
                "remoteProtocol": "oauth_protected_streamable_http",
                "credentialedHttp": "exact_host_no_proxy_no_redirect",
                "logs": "structured_json_stderr",
                "telemetry": "ores-otel_bounded_low_cardinality",
                "authentication": "shared-auth_when_a_product_boundary_requires_it",
                "authorization": "product_local_never_inferred_from_identity",
                "dependencyManagement": "zed-pkg_with_immutable_git_revisions",
                "secrets": "sops_age_env_injection_never_cli_flags_or_logs",
            }),
        )
    }

    /// Read the exact GitHub organization and latest MCP-server workflow run.
    #[tool(
        description = "Read bounded metadata for this exact GitHub organization and its MCP repository's latest Actions run.",
        annotations(
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = true
        )
    )]
    async fn github_posture(
        &self,
        Parameters(_): Parameters<NoArguments>,
    ) -> Result<String, String> {
        self.provider_json(self.providers.github().await)
    }

    /// Verify one configured AWS account and exact EKS cluster allowlist.
    #[tool(
        description = "Verify the configured organization AWS account and list only explicitly allowed EKS clusters; missing scope reports not_configured.",
        annotations(
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = true
        )
    )]
    async fn aws_posture(&self, Parameters(_): Parameters<NoArguments>) -> Result<String, String> {
        self.provider_json(self.providers.aws().await)
    }

    /// Read one configured Google Cloud project and enabled services.
    #[tool(
        description = "Read the exact configured organization Google Cloud project and a bounded enabled-service projection.",
        annotations(
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = true
        )
    )]
    async fn gcp_posture(&self, Parameters(_): Parameters<NoArguments>) -> Result<String, String> {
        self.provider_json(self.providers.gcp().await)
    }

    /// Read one exact Supabase project's auth settings and Data API shape.
    #[tool(
        description = "Read bounded public-auth settings and Data API path metadata for the exact configured organization Supabase project.",
        annotations(
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = true
        )
    )]
    async fn supabase_posture(
        &self,
        Parameters(_): Parameters<NoArguments>,
    ) -> Result<String, String> {
        self.provider_json(self.providers.supabase().await)
    }

    /// Read organization-filtered Neon projects and optional exact branches.
    #[tool(
        description = "Read bounded organization-filtered Neon project and optional exact branch state without connection details.",
        annotations(
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = true
        )
    )]
    async fn neon_posture(&self, Parameters(_): Parameters<NoArguments>) -> Result<String, String> {
        self.provider_json(self.providers.neon().await)
    }

    /// Read one exact Cloudflare zone and safe DNS metadata.
    #[tool(
        description = "Read the exact configured organization Cloudflare zone and optional bounded DNS metadata without record content.",
        annotations(
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = true
        )
    )]
    async fn cloudflare_posture(
        &self,
        Parameters(_): Parameters<NoArguments>,
    ) -> Result<String, String> {
        self.provider_json(self.providers.cloudflare().await)
    }

    /// Inspect workloads in the exact organization Kubernetes namespace.
    #[tool(
        description = "Read bounded deployment and pod readiness from ORESoftware/k8s-cluster in this organization's exact namespace and part-of selector.",
        annotations(
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = true
        )
    )]
    async fn k8s_posture(&self, Parameters(_): Parameters<NoArguments>) -> Result<String, String> {
        self.provider_json(self.providers.kubernetes().await)
    }

    /// Request read-only service and dependency snapshots over exact NATS subjects.
    #[tool(
        description = "Request bounded organization service and dependency snapshots over two exact NATS subjects; arbitrary subjects and wildcards are rejected.",
        annotations(
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = true
        )
    )]
    async fn nats_posture(&self, Parameters(_): Parameters<NoArguments>) -> Result<String, String> {
        self.provider_json(self.providers.nats().await)
    }

    /// Compose all eight provider reads into one organization readiness view.
    #[tool(
        description = "Compose GitHub, AWS, GCP, Supabase, Neon, Cloudflare, ORESoftware/k8s-cluster, and NATS posture using five honest states.",
        annotations(
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = true
        )
    )]
    async fn organization_posture(
        &self,
        Parameters(_): Parameters<NoArguments>,
    ) -> Result<String, String> {
        let (github, aws, gcp, supabase, neon, cloudflare, kubernetes, nats) = tokio::join!(
            self.providers.github(),
            self.providers.aws(),
            self.providers.gcp(),
            self.providers.supabase(),
            self.providers.neon(),
            self.providers.cloudflare(),
            self.providers.kubernetes(),
            self.providers.nats(),
        );
        let reports = vec![
            github, aws, gcp, supabase, neon, cloudflare, kubernetes, nats,
        ];
        let ready = reports
            .iter()
            .filter(|report| report.state() == "ready")
            .count();
        let state = if ready == reports.len() {
            "ready"
        } else if reports
            .iter()
            .any(|report| matches!(report.state(), "unauthorized" | "forbidden"))
        {
            "blocked"
        } else if reports.iter().any(|report| report.state() == "degraded") {
            "degraded"
        } else {
            "not_configured"
        };
        self.successful_json(
            ToolClass::Health,
            json!({
                "organization": self.spec.organization,
                "repository": self.spec.repository,
                "state": state,
                "readyProviders": ready,
                "providerCount": reports.len(),
                "providers": reports,
            }),
        )
    }
}

#[tool_handler(router = self.tool_router)]
impl ServerHandler for OrgMcpServer {
    async fn list_resources(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListResourcesResult, ErrorData> {
        Ok(ListResourcesResult::with_all_items(
            catalog::resources(self.spec)
                .into_iter()
                .map(|resource| {
                    Resource::new(resource.uri, resource.name)
                        .with_description(resource.description)
                        .with_mime_type(resource.mime)
                })
                .collect(),
        ))
    }

    async fn read_resource(
        &self,
        request: ReadResourceRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> Result<ReadResourceResult, ErrorData> {
        let resources = catalog::resources(self.spec);
        match resources
            .into_iter()
            .find(|resource| resource.uri == request.uri)
        {
            Some(resource) => Ok(ReadResourceResult::new(vec![ResourceContents::text(
                resource.body,
                &request.uri,
            )
            .with_mime_type(resource.mime)])),
            None => Err(ErrorData::resource_not_found(
                "unknown organization resource",
                None,
            )),
        }
    }

    async fn list_prompts(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListPromptsResult, ErrorData> {
        Ok(ListPromptsResult::with_all_items(
            catalog::prompts(self.spec)
                .into_iter()
                .map(|prompt| Prompt::new(prompt.name, Some(prompt.description), None))
                .collect(),
        ))
    }

    async fn get_prompt(
        &self,
        request: GetPromptRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> Result<GetPromptResult, ErrorData> {
        match catalog::prompts(self.spec)
            .into_iter()
            .find(|prompt| prompt.name == request.name)
        {
            Some(prompt) => Ok(GetPromptResult::new(vec![PromptMessage::new_text(
                Role::User,
                prompt.text,
            )])
            .with_description(prompt.description)),
            None => Err(ErrorData::invalid_params(
                "unknown organization prompt",
                None,
            )),
        }
    }

    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(
            ServerCapabilities::builder()
                .enable_tools()
                .enable_resources()
                .enable_prompts()
                .build(),
        )
            .with_server_info(Implementation::new(
                self.spec.service_name,
                self.spec.version,
            ))
            .with_instructions(format!(
                "Read-only, organization-specific diagnostics for {} across Cursor, ChatGPT/OpenAI, Claude/Anthropic, Gemini, Grok, and Qwen. Start with organization_posture for GitHub, AWS, GCP, Supabase, Neon, Cloudflare, ORESoftware/k8s-cluster, and NATS; use org_identity and zed_dependency_graph for exact ownership and dependencies. Missing configuration is an explicit state, never success.",
                self.spec.organization
            ))
    }
}

#[cfg(test)]
#[derive(Debug, PartialEq, Eq)]
enum CappedLine {
    Eof,
    Discarded,
    Bytes(Vec<u8>),
}

struct LineCappedReader<R> {
    inner: BufReader<R>,
    line: Vec<u8>,
    discarding: bool,
    pending: Vec<u8>,
    pending_offset: usize,
}

impl<R: AsyncRead + Unpin> AsyncRead for LineCappedReader<R> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = &mut *self;
        if this.pending_offset < this.pending.len() {
            copy_pending(this, buf);
            return Poll::Ready(Ok(()));
        }
        loop {
            let available = ready!(Pin::new(&mut this.inner).poll_fill_buf(cx))?;
            if available.is_empty() {
                return Poll::Ready(Ok(()));
            }
            if let Some(offset) = available.iter().position(|byte| *byte == b'\n') {
                let consume = offset + 1;
                if this.discarding || this.line.len() + offset > MAX_STDIO_FRAME_BYTES {
                    Pin::new(&mut this.inner).consume(consume);
                    this.line.clear();
                    this.discarding = false;
                    tracing::warn!("discarded invalid or oversized MCP stdio frame");
                    continue;
                }
                this.line.extend_from_slice(&available[..offset]);
                Pin::new(&mut this.inner).consume(consume);
                if this.line.last() == Some(&b'\r') {
                    this.line.pop();
                }
                this.pending.append(&mut this.line);
                this.pending.push(b'\n');
                this.pending_offset = 0;
                copy_pending(this, buf);
                return Poll::Ready(Ok(()));
            }
            if this.discarding || this.line.len() + available.len() > MAX_STDIO_FRAME_BYTES {
                let consumed = available.len();
                Pin::new(&mut this.inner).consume(consumed);
                this.line.clear();
                this.discarding = true;
                continue;
            }
            let consumed = available.len();
            this.line.extend_from_slice(available);
            Pin::new(&mut this.inner).consume(consumed);
        }
    }
}

fn copy_pending<R>(this: &mut LineCappedReader<R>, buf: &mut ReadBuf<'_>) {
    let rest = &this.pending[this.pending_offset..];
    let copied = rest.len().min(buf.remaining());
    buf.put_slice(&rest[..copied]);
    this.pending_offset += copied;
    if this.pending_offset == this.pending.len() {
        this.pending.clear();
        this.pending_offset = 0;
    }
}

#[cfg(test)]
async fn read_capped_line<R>(reader: &mut R, max_bytes: usize) -> io::Result<CappedLine>
where
    R: tokio::io::AsyncBufRead + Unpin,
{
    use tokio::io::AsyncBufReadExt;
    let mut data = Vec::new();
    let mut discarding = false;
    loop {
        let available = reader.fill_buf().await?;
        if available.is_empty() {
            return Ok(if data.is_empty() && !discarding {
                CappedLine::Eof
            } else if discarding || data.len() > max_bytes {
                CappedLine::Discarded
            } else {
                CappedLine::Bytes(data)
            });
        }
        if let Some(offset) = available.iter().position(|byte| *byte == b'\n') {
            if discarding || data.len() + offset > max_bytes {
                reader.consume(offset + 1);
                return Ok(CappedLine::Discarded);
            }
            data.extend_from_slice(&available[..offset]);
            reader.consume(offset + 1);
            if data.last() == Some(&b'\r') {
                data.pop();
            }
            return Ok(CappedLine::Bytes(data));
        }
        if discarding || data.len() + available.len() > max_bytes {
            let consumed = available.len();
            reader.consume(consumed);
            discarding = true;
            data.clear();
            continue;
        }
        let consumed = available.len();
        data.extend_from_slice(available);
        reader.consume(consumed);
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
    let providers = ProviderContext::capture(spec);
    let server = ExactProtocol::new(
        OrgMcpServer::new(spec, telemetry_guard.status(), providers)?,
        ProtocolVersion::V_2025_11_25,
    );
    tracing::info!(
        service.name = spec.service_name,
        service.namespace = spec.organization,
        service.version = spec.version,
        transport = "stdio",
        protocol = "2025-11-25",
        access.mode = "read_only",
        "starting organization MCP server"
    );
    let server_span = tracing::info_span!(
        "mcp.server",
        rpc.system = "mcp",
        transport = "stdio",
        access.mode = "read_only"
    );
    let (stdin, stdout) = stdio();
    let stdin = LineCappedReader {
        inner: BufReader::new(stdin),
        line: Vec::new(),
        discarding: false,
        pending: Vec::new(),
        pending_offset: 0,
    };
    let service = server
        .serve((stdin, stdout))
        .instrument(server_span.clone())
        .await?;
    service.waiting().instrument(server_span).await?;
    drop(telemetry_guard);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rmcp::{service::RxJsonRpcMessage, transport::async_rw::JsonRpcMessageCodec, RoleServer};
    use tokio::io::AsyncReadExt;
    use tokio_util::bytes::BytesMut;
    use tokio_util::codec::Decoder;

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
        let tools = router.list_all();
        let names = tools
            .iter()
            .map(|tool| tool.name.to_string())
            .collect::<Vec<_>>();
        assert_eq!(names.len(), 15);
        for name in [
            "org_identity",
            "zed_dependency_graph",
            "telemetry_status",
            "shared_auth_policy",
            "environment_policy",
            "security_baseline",
            "github_posture",
            "aws_posture",
            "gcp_posture",
            "supabase_posture",
            "neon_posture",
            "cloudflare_posture",
            "k8s_posture",
            "nats_posture",
            "organization_posture",
        ] {
            assert!(names.iter().any(|candidate| candidate == name));
        }
        for tool in tools {
            let descriptor = serde_json::to_value(tool).expect("serialize tool descriptor");
            assert_eq!(
                descriptor.pointer("/inputSchema/additionalProperties"),
                Some(&Value::Bool(false))
            );
        }
        assert!(serde_json::from_value::<NoArguments>(json!({})).is_ok());
        assert!(serde_json::from_value::<NoArguments>(json!({"unexpected": true})).is_err());
    }

    #[test]
    fn stdio_codec_rejects_oversized_frames() {
        let mut codec = JsonRpcMessageCodec::<RxJsonRpcMessage<RoleServer>>::new_with_max_length(
            MAX_STDIO_FRAME_BYTES,
        );
        let oversized = vec![b' '; MAX_STDIO_FRAME_BYTES + 2];
        let mut frame = BytesMut::from(oversized.as_slice());
        let error = codec
            .decode(&mut frame)
            .expect_err("oversized stdio frame must be rejected");
        assert!(error.to_string().contains("max line length exceeded"));
    }

    #[tokio::test]
    async fn oversized_stdio_line_is_discarded_without_closing_the_stream() {
        let mut input = vec![b'x'; MAX_STDIO_FRAME_BYTES + 1];
        input.push(b'\n');
        input.extend_from_slice(br#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#);
        input.push(b'\n');
        let mut reader = BufReader::new(input.as_slice());
        assert_eq!(
            read_capped_line(&mut reader, MAX_STDIO_FRAME_BYTES)
                .await
                .expect("read oversized line"),
            CappedLine::Discarded
        );
        match read_capped_line(&mut reader, MAX_STDIO_FRAME_BYTES)
            .await
            .expect("read initialize line")
        {
            CappedLine::Bytes(bytes) => {
                assert!(bytes.starts_with(br#"{"jsonrpc":"2.0""#));
            }
            other => panic!("expected initialize bytes, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn capped_async_read_skips_oversized_line_and_keeps_the_next_frame() {
        let mut input = vec![b'x'; MAX_STDIO_FRAME_BYTES + 1];
        input.push(b'\n');
        input.extend_from_slice(br#"{"jsonrpc":"2.0","id":1,"method":"initialize"}"#);
        input.push(b'\n');
        let mut reader = LineCappedReader {
            inner: BufReader::new(input.as_slice()),
            line: Vec::new(),
            discarding: false,
            pending: Vec::new(),
            pending_offset: 0,
        };
        let mut recovered = String::new();
        reader
            .read_to_string(&mut recovered)
            .await
            .expect("read remaining frames");
        assert_eq!(
            recovered,
            "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\"}\n"
        );
    }
}
