//! Read-first provider adapters for organization-specific MCP servers.
//!
//! This crate owns bounded, low-level provider reads and the shared five-state
//! result vocabulary. Consumer repositories still own organization scope,
//! configuration discovery, MCP tool descriptions, resource authorization,
//! mutation gates, result composition, and the final output ceiling.

#![forbid(unsafe_code)]

use std::{error::Error, fmt};

use ore_mcp_http::{BoundedResponse, HttpClientError, UpstreamHttpState};
use serde::Serialize;
use serde_json::Value;

#[cfg(feature = "aws")]
pub mod aws;
#[cfg(feature = "http-providers")]
pub mod cloudflare;
#[cfg(feature = "http-providers")]
pub mod gcp;
#[cfg(feature = "http-providers")]
pub mod github;
#[cfg(feature = "kubernetes")]
pub mod kubernetes;
#[cfg(feature = "nats")]
pub mod nats;
#[cfg(feature = "http-providers")]
pub mod neon;
#[cfg(feature = "http-providers")]
pub mod supabase;

/// Provider identities required by the fleet-parity contract.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderId {
    /// GitHub organization, repository, and workflow data.
    GitHub,
    /// Amazon Web Services identity and organization workloads.
    Aws,
    /// Google Cloud project and workload data.
    Gcp,
    /// Supabase auth, database, and realtime project data.
    Supabase,
    /// Neon project, branch, and compute data.
    Neon,
    /// Cloudflare zone, DNS, worker, and routing data.
    Cloudflare,
    /// The ORESoftware Kubernetes deployment cluster.
    K8sCluster,
    /// NATS request/reply and JetStream data owned by the organization.
    Nats,
}

impl ProviderId {
    /// Returns the stable contract spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::GitHub => "github",
            Self::Aws => "aws",
            Self::Gcp => "gcp",
            Self::Supabase => "supabase",
            Self::Neon => "neon",
            Self::Cloudflare => "cloudflare",
            Self::K8sCluster => "k8s_cluster",
            Self::Nats => "nats",
        }
    }
}

/// Honest runtime state for one provider operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IntegrationState {
    /// The configured provider returned a valid scoped result.
    Ready,
    /// Required non-secret or secret configuration is absent.
    NotConfigured,
    /// The provider or transport could not produce a trustworthy result.
    Degraded,
    /// The credential is missing, malformed, invalid, or expired.
    Unauthorized,
    /// The credential is valid but not permitted for this operation.
    Forbidden,
}

impl IntegrationState {
    /// Returns the stable contract spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ready => "ready",
            Self::NotConfigured => "not_configured",
            Self::Degraded => "degraded",
            Self::Unauthorized => "unauthorized",
            Self::Forbidden => "forbidden",
        }
    }
}

impl From<UpstreamHttpState> for IntegrationState {
    fn from(value: UpstreamHttpState) -> Self {
        match value {
            UpstreamHttpState::Ready => Self::Ready,
            UpstreamHttpState::Unauthorized => Self::Unauthorized,
            UpstreamHttpState::Forbidden => Self::Forbidden,
            UpstreamHttpState::Degraded => Self::Degraded,
        }
    }
}

/// Value-free adapter configuration failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IntegrationConfigError {
    /// An organization, account, tenant, or namespace identifier is invalid.
    InvalidOrganizationScope,
    /// A repository, project, zone, or subject identifier is invalid.
    InvalidResourceScope,
    /// A configured base URL or exact expected host is invalid.
    InvalidEndpoint,
    /// A timeout, byte ceiling, or result limit is outside the supported range.
    InvalidLimit,
}

impl fmt::Display for IntegrationConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidOrganizationScope => {
                formatter.write_str("invalid provider organization scope")
            }
            Self::InvalidResourceScope => formatter.write_str("invalid provider resource scope"),
            Self::InvalidEndpoint => formatter.write_str("invalid provider endpoint"),
            Self::InvalidLimit => formatter.write_str("invalid provider operation limit"),
        }
    }
}

impl Error for IntegrationConfigError {}

/// Bounded, serializable result from one concrete provider read.
#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProviderRead {
    provider: ProviderId,
    operation: &'static str,
    state: IntegrationState,
    diagnostic_code: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    http_status: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    payload: Option<Value>,
}

impl ProviderRead {
    /// Returns the provider that was queried.
    #[must_use]
    pub const fn provider(&self) -> ProviderId {
        self.provider
    }

    /// Returns the stable operation name.
    #[must_use]
    pub const fn operation(&self) -> &'static str {
        self.operation
    }

    /// Returns the five-state outcome.
    #[must_use]
    pub const fn state(&self) -> IntegrationState {
        self.state
    }

    /// Returns a value-free diagnostic code suitable for MCP output.
    #[must_use]
    pub const fn diagnostic_code(&self) -> &'static str {
        self.diagnostic_code
    }

    /// Returns the upstream status without response headers or URL data.
    #[must_use]
    pub const fn http_status(&self) -> Option<u16> {
        self.http_status
    }

    /// Returns the provider-specific, deliberately projected payload.
    #[must_use]
    pub const fn payload(&self) -> Option<&Value> {
        self.payload.as_ref()
    }

    /// Returns an honest result when a consumer cannot construct a provider
    /// adapter because required account, project, endpoint, or credential
    /// configuration is absent.
    ///
    /// Consumers should call this before adapter construction instead of
    /// inventing placeholder scope identifiers. `operation` must be a stable,
    /// non-secret name owned by the calling server.
    #[must_use]
    pub fn not_configured(provider: ProviderId, operation: &'static str) -> Self {
        Self {
            provider,
            operation,
            state: IntegrationState::NotConfigured,
            diagnostic_code: "not_configured",
            http_status: None,
            payload: None,
        }
    }

    /// Returns a value-free degraded result for failures that occur before a
    /// scoped adapter can safely issue its provider request.
    ///
    /// Adapter methods already translate their own transport and payload
    /// failures. This constructor is for consumer-owned client creation, such
    /// as loading the in-cluster Kubernetes client or connecting to NATS.
    #[must_use]
    pub fn degraded(provider: ProviderId, operation: &'static str) -> Self {
        Self {
            provider,
            operation,
            state: IntegrationState::Degraded,
            diagnostic_code: "provider_unavailable",
            http_status: None,
            payload: None,
        }
    }

    #[cfg(any(feature = "aws", feature = "kubernetes", feature = "nats"))]
    pub(crate) fn ready(provider: ProviderId, operation: &'static str, payload: Value) -> Self {
        Self {
            provider,
            operation,
            state: IntegrationState::Ready,
            diagnostic_code: "ready",
            http_status: None,
            payload: Some(payload),
        }
    }
}

pub(crate) fn http_failure(
    provider: ProviderId,
    operation: &'static str,
    error: HttpClientError,
) -> ProviderRead {
    let state = if matches!(error, HttpClientError::InvalidCredential) {
        IntegrationState::Unauthorized
    } else {
        IntegrationState::Degraded
    };
    ProviderRead {
        provider,
        operation,
        state,
        diagnostic_code: if state == IntegrationState::Unauthorized {
            "invalid_credential"
        } else {
            "transport_or_policy_failure"
        },
        http_status: None,
        payload: None,
    }
}

pub(crate) fn project_http<F>(
    provider: ProviderId,
    operation: &'static str,
    response: BoundedResponse,
    project: F,
) -> ProviderRead
where
    F: FnOnce(Value) -> Option<Value>,
{
    let state = IntegrationState::from(response.state());
    let status = response.status();
    if state != IntegrationState::Ready {
        return ProviderRead {
            provider,
            operation,
            state,
            diagnostic_code: state.as_str(),
            http_status: Some(status),
            payload: None,
        };
    }
    let payload = serde_json::from_slice(response.body())
        .ok()
        .and_then(project);
    match payload {
        Some(payload) => ProviderRead {
            provider,
            operation,
            state,
            diagnostic_code: "ready",
            http_status: Some(status),
            payload: Some(payload),
        },
        None => ProviderRead {
            provider,
            operation,
            state: IntegrationState::Degraded,
            diagnostic_code: "invalid_provider_payload",
            http_status: Some(status),
            payload: None,
        },
    }
}

pub(crate) fn configured_credential(value: Option<&str>) -> Option<&str> {
    value.filter(|candidate| !candidate.trim().is_empty())
}

pub(crate) fn valid_identifier(value: &str, max_bytes: usize) -> bool {
    !value.is_empty()
        && value.len() <= max_bytes
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provider_and_state_spellings_are_stable() {
        assert_eq!(ProviderId::GitHub.as_str(), "github");
        assert_eq!(ProviderId::K8sCluster.as_str(), "k8s_cluster");
        assert_eq!(IntegrationState::NotConfigured.as_str(), "not_configured");
        assert_eq!(IntegrationState::Forbidden.as_str(), "forbidden");
    }

    #[test]
    fn credential_presence_and_identifiers_fail_closed() {
        assert_eq!(configured_credential(None), None);
        assert_eq!(configured_credential(Some("  ")), None);
        assert_eq!(configured_credential(Some("token")), Some("token"));
        assert!(valid_identifier("org-repo_1.rs", 64));
        assert!(!valid_identifier("org/repo", 64));
        assert!(!valid_identifier("bad\nname", 64));
    }

    #[test]
    fn provider_results_serialize_without_empty_payloads() {
        let result = ProviderRead::not_configured(ProviderId::Neon, "list_projects");
        let value = serde_json::to_value(result).expect("serializable result");
        assert_eq!(value["provider"], "neon");
        assert_eq!(value["state"], "not_configured");
        assert!(value.get("payload").is_none());
        assert!(value.get("httpStatus").is_none());
    }
}
