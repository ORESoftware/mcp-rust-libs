//! Shared Auth protected Streamable HTTP lifecycle for remote MCP clients.

use std::io;
use std::net::SocketAddr;

use ore_mcp_remote::{
    protected_mcp_router, AssuranceLevel, RealmClaim, RemoteAuthPolicy, RemoteMcpConfig,
    SharedAuthVerifier,
};
use rmcp::ServerHandler;
use url::Url;

use crate::providers::ProviderContext;
use crate::{validate_spec, OrgMcpServer, OrgSpec, ParityAugmented};

const DEFAULT_BIND: &str = "127.0.0.1:8090";
const DEFAULT_CLIENTS: &str =
    "cursor,openai-chatgpt,anthropic-claude,google-gemini,xai-grok,alibaba-qwen";
const DEFAULT_ORIGINS: &str = "https://cursor.com,https://chatgpt.com,https://platform.openai.com,https://claude.ai,https://gemini.google.com,https://grok.com,https://chat.qwen.ai";
const REQUEST_MAX_BYTES: usize = 256 * 1024;
const RESPONSE_MAX_BYTES: usize = 512 * 1024;
const REMOTE_AUTHORIZATION_BOUNDARY: &str = "Bearer Shared Auth access token";
const CREDENTIALED_HTTP_POLICY: &str =
    "ore-mcp-http redirect::Policy::none with .no_proxy() exact-host requests";

struct RemoteLaunch {
    bind: SocketAddr,
    config: RemoteMcpConfig,
}

#[derive(Default)]
struct RemoteEnvironment {
    public_resource: Option<String>,
    issuer: Option<String>,
    jwks_url: Option<String>,
    clients: Option<String>,
    origins: Option<String>,
    bind: Option<String>,
}

impl RemoteEnvironment {
    fn capture() -> Self {
        Self {
            public_resource: env_value("ORE_MCP_PUBLIC_RESOURCE"),
            issuer: env_value("SHARED_AUTH_ISSUER"),
            jwks_url: env_value("SHARED_AUTH_JWKS_URL"),
            clients: env_value("ORE_MCP_OAUTH_CLIENT_IDS"),
            origins: env_value("ORE_MCP_ALLOWED_ORIGINS"),
            bind: env_value("ORE_MCP_HTTP_BIND"),
        }
    }
}

/// Starts one organization server at an OAuth-protected final-protocol `/mcp` route.
///
/// # Errors
///
/// Fails before binding when the organization identity, exact public resource,
/// Shared Auth issuer/JWKS relationship, authorized clients, origins, realm,
/// assurance, scope, role, or socket address is missing or invalid. JWKS is
/// warmed before the listener accepts traffic.
pub async fn run_http(spec: OrgSpec) -> Result<(), Box<dyn std::error::Error>> {
    validate_spec(spec)?;
    let launch = remote_launch(spec, &RemoteEnvironment::capture()).map_err(io::Error::other)?;
    let telemetry_guard =
        ores_mcp_server_core_libs::observability::init(spec.service_name, spec.organization);
    let providers = ProviderContext::capture(spec);
    let server = OrgMcpServer::new(spec, telemetry_guard.status(), providers)?;
    serve_http_handler(server, spec, launch).await?;
    drop(telemetry_guard);
    Ok(())
}

/// Adds fleet parity to a richer organization handler and serves it over an
/// OAuth-protected final-protocol `/mcp` route.
///
/// The caller owns primary-handler configuration and telemetry initialization.
/// Shared Auth validation, exact-host policy, body bounds, and the listener are
/// still owned by this crate.
///
/// # Errors
///
/// Fails before binding for invalid identity, shared tool collisions, invalid
/// authorization configuration, JWKS warmup failure, or listener failure.
pub async fn run_augmented_http<S>(
    primary: S,
    spec: OrgSpec,
) -> Result<(), Box<dyn std::error::Error>>
where
    S: ServerHandler + Clone,
{
    validate_spec(spec)?;
    let launch = remote_launch(spec, &RemoteEnvironment::capture()).map_err(io::Error::other)?;
    let server = ParityAugmented::new(primary, spec)?;
    serve_http_handler(server, spec, launch).await
}

async fn serve_http_handler<S>(
    server: S,
    spec: OrgSpec,
    launch: RemoteLaunch,
) -> Result<(), Box<dyn std::error::Error>>
where
    S: ServerHandler + Clone,
{
    let verifier = SharedAuthVerifier::new(launch.config.auth().clone())?;
    verifier.warm().await?;
    let router = protected_mcp_router(launch.config, verifier, move || Ok(server.clone()));
    let listener = tokio::net::TcpListener::bind(launch.bind).await?;
    tracing::info!(
        service.name = spec.service_name,
        service.namespace = spec.organization,
        service.version = spec.version,
        transport = "streamable_http",
        listen = %launch.bind,
        protocol = "2025-11-25",
        authorization = REMOTE_AUTHORIZATION_BOUNDARY,
        credentialed_http = CREDENTIALED_HTTP_POLICY,
        access.mode = "read_only",
        "starting authenticated organization MCP server"
    );
    axum::serve(listener, router).await?;
    Ok(())
}

fn remote_launch(spec: OrgSpec, env: &RemoteEnvironment) -> Result<RemoteLaunch, String> {
    let resource = required(env.public_resource.as_deref(), "ORE_MCP_PUBLIC_RESOURCE")?;
    let issuer = required(env.issuer.as_deref(), "SHARED_AUTH_ISSUER")?;
    let jwks_url = required(env.jwks_url.as_deref(), "SHARED_AUTH_JWKS_URL")?;
    let clients = csv(
        env.clients.as_deref().unwrap_or(DEFAULT_CLIENTS),
        "authorized OAuth clients",
    )?;
    let origins = csv(
        env.origins.as_deref().unwrap_or(DEFAULT_ORIGINS),
        "allowed origins",
    )?;
    let resource_url = Url::parse(resource).map_err(|_| "invalid remote MCP resource")?;
    let host = match (resource_url.host_str(), resource_url.port()) {
        (Some(host), Some(port)) => format!("{host}:{port}"),
        (Some(host), None) => host.to_owned(),
        (None, _) => return Err("invalid remote MCP resource".to_owned()),
    };
    let slug = scope_slug(spec.organization);
    let auth = RemoteAuthPolicy::new(
        resource,
        issuer,
        jwks_url,
        clients,
        RealmClaim::Project,
        spec.organization,
        AssuranceLevel::Aal2,
        ["mcp:read".to_owned(), format!("{slug}:inspect")],
        [format!("{slug}_viewer"), format!("{slug}_operator")],
    )
    .map_err(|error| error.to_string())?;
    let config = RemoteMcpConfig::new(auth, [host], origins)
        .map_err(|error| error.to_string())?
        .with_stateful_mode(false)
        .with_body_limits(REQUEST_MAX_BYTES, RESPONSE_MAX_BYTES)
        .map_err(|error| error.to_string())?;
    let bind = env
        .bind
        .as_deref()
        .unwrap_or(DEFAULT_BIND)
        .parse::<SocketAddr>()
        .map_err(|_| "invalid ORE_MCP_HTTP_BIND socket address".to_owned())?;
    Ok(RemoteLaunch { bind, config })
}

fn required<'a>(value: Option<&'a str>, key: &str) -> Result<&'a str, String> {
    value.ok_or_else(|| format!("required remote MCP setting {key} is missing"))
}

fn csv(value: &str, label: &str) -> Result<Vec<String>, String> {
    let values = value
        .split(',')
        .map(str::trim)
        .filter(|item| !item.is_empty())
        .map(str::to_owned)
        .collect::<Vec<_>>();
    if values.is_empty() || values.len() > 64 {
        return Err(format!("invalid {label}"));
    }
    Ok(values)
}

fn env_value(key: &str) -> Option<String> {
    std::env::var(key)
        .ok()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
}

fn scope_slug(value: &str) -> String {
    value
        .bytes()
        .map(|byte| {
            if byte.is_ascii_alphanumeric() {
                byte.to_ascii_lowercase() as char
            } else {
                '_'
            }
        })
        .collect::<String>()
        .trim_matches('_')
        .to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    const DEPENDENCIES: &[&str] = &["shared-auth/shared-auth-clients"];

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

    fn valid_env() -> RemoteEnvironment {
        RemoteEnvironment {
            public_resource: Some("https://mcp.example.org/mcp".into()),
            issuer: Some("https://auth.example.org".into()),
            jwks_url: Some("https://auth.example.org/.well-known/jwks.json".into()),
            ..RemoteEnvironment::default()
        }
    }

    #[test]
    fn remote_policy_covers_all_six_client_families() {
        let launch = remote_launch(spec(), &valid_env()).expect("valid remote configuration");
        assert!(!launch.config.stateful());
        assert_eq!(launch.config.auth().authorized_clients().len(), 6);
        assert_eq!(launch.config.auth().realm(), "example-org");
        assert_eq!(launch.config.auth().required_scopes().len(), 2);
        assert_eq!(
            launch.config.auth().minimum_assurance(),
            AssuranceLevel::Aal2
        );
    }

    #[test]
    fn missing_or_cross_host_auth_configuration_fails_closed() {
        assert!(remote_launch(spec(), &RemoteEnvironment::default()).is_err());
        let mut env = valid_env();
        env.jwks_url = Some("https://attacker.invalid/jwks.json".into());
        assert!(remote_launch(spec(), &env).is_err());
    }

    #[test]
    fn public_resource_must_be_exact_mcp_https_url() {
        let mut env = valid_env();
        env.public_resource = Some("https://mcp.example.org/not-mcp".into());
        assert!(remote_launch(spec(), &env).is_err());
    }
}
