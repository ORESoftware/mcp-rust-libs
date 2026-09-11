//! Concrete, bounded HTTP reads for credentialed MCP integrations.
//!
//! The client deliberately owns the controls that are easy to omit when every
//! product server constructs `reqwest::Client` independently: exact-host
//! validation, redirect denial, ambient-proxy denial, total deadlines,
//! sensitive credential headers, and incremental response-body limits.

use std::{error::Error, fmt, time::Duration};

use ore_mcp_safety::valid_header_value;
use reqwest::{
    header::{HeaderName, HeaderValue, AUTHORIZATION, COOKIE, PROXY_AUTHORIZATION, SET_COOKIE},
    redirect::Policy,
    Client, Request, StatusCode,
};

use crate::{BodyLimitError, BoundedBody, HttpPolicy, HttpPolicyError};

const MAX_CREDENTIAL_BYTES: usize = 8 * 1024;
const MAX_PUBLIC_HEADER_BYTES: usize = 1024;

/// Credential headers supported by the shared read-only client.
///
/// The enum intentionally has no `Debug`, `Display`, serialization, or accessors
/// that could make credential values convenient to log. Supabase needs both an
/// `Authorization` bearer and its `apikey` header; the other HTTP providers in
/// the fleet use the bearer-only variant.
pub enum CredentialHeaders<'a> {
    /// No credential is attached. The endpoint is still exact-host checked.
    None,
    /// One OAuth, API-token, or access-token bearer.
    Bearer(&'a str),
    /// A bearer plus Supabase's required `apikey` header.
    BearerWithApiKey {
        /// The value placed after the `Bearer` scheme.
        bearer: &'a str,
        /// The value placed in the sensitive `apikey` header.
        api_key: &'a str,
    },
}

/// Stable state derived from an upstream HTTP response.
///
/// `not_configured` is intentionally absent: configuration is decided before a
/// request is built. Transport errors and non-success/non-auth statuses map to
/// `degraded` at the product adapter boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UpstreamHttpState {
    /// The upstream accepted the read request.
    Ready,
    /// The credential is missing, invalid, or expired.
    Unauthorized,
    /// The credential is valid but lacks authority for the requested scope.
    Forbidden,
    /// The upstream returned a response that does not prove readiness.
    Degraded,
}

impl UpstreamHttpState {
    /// Returns the parity-contract spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ready => "ready",
            Self::Unauthorized => "unauthorized",
            Self::Forbidden => "forbidden",
            Self::Degraded => "degraded",
        }
    }
}

impl fmt::Display for UpstreamHttpState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// A response whose body was bounded before buffering.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BoundedResponse {
    status: u16,
    body: Vec<u8>,
}

impl BoundedResponse {
    /// Returns the upstream HTTP status code.
    #[must_use]
    pub const fn status(&self) -> u16 {
        self.status
    }

    /// Returns the complete body, guaranteed not to exceed the client policy.
    #[must_use]
    pub fn body(&self) -> &[u8] {
        &self.body
    }

    /// Consumes the response and returns the bounded body.
    #[must_use]
    pub fn into_body(self) -> Vec<u8> {
        self.body
    }

    /// Classifies the response into the shared provider-state vocabulary.
    #[must_use]
    pub fn state(&self) -> UpstreamHttpState {
        classify_status(self.status)
    }
}

/// A reusable read-only HTTP client with fail-closed credential behavior.
#[derive(Clone)]
pub struct HardenedHttpClient {
    inner: Client,
    policy: HttpPolicy,
}

impl HardenedHttpClient {
    /// Constructs a client with redirects and ambient proxies disabled.
    ///
    /// # Errors
    ///
    /// Returns a value-free [`HttpClientError`] when the policy is invalid or
    /// the TLS/HTTP client cannot be constructed.
    pub fn new(policy: HttpPolicy) -> Result<Self, HttpClientError> {
        if policy.follow_redirects || policy.timeout_ms == 0 || policy.timeout_ms > 60_000 {
            return Err(HttpClientError::InvalidPolicy);
        }
        BoundedBody::new(policy.max_body_bytes).map_err(HttpClientError::BodyLimit)?;
        let deadline = Duration::from_millis(policy.timeout_ms);
        let inner = Client::builder()
            .redirect(Policy::none())
            .no_proxy()
            .connect_timeout(deadline)
            .timeout(deadline)
            .user_agent("ore-mcp-http/0.1")
            .build()
            .map_err(|_| HttpClientError::Build)?;
        Ok(Self { inner, policy })
    }

    /// Returns the immutable policy used for every request.
    #[must_use]
    pub const fn policy(&self) -> HttpPolicy {
        self.policy
    }

    /// Executes one exact-host, bounded `GET` request.
    ///
    /// Public headers are intended for values such as GitHub's API version or
    /// an `Accept` media type. Credential-bearing names are rejected there so
    /// callers cannot bypass the sensitive-header path.
    ///
    /// # Errors
    ///
    /// Returns a value-free error for unsafe URLs or headers, request failures,
    /// and declared or streamed response-body overflow.
    pub async fn get(
        &self,
        endpoint: &str,
        allowed_hosts: &[&str],
        credentials: CredentialHeaders<'_>,
        public_headers: &[(&str, &str)],
    ) -> Result<BoundedResponse, HttpClientError> {
        let request = self.prepare_get(endpoint, allowed_hosts, credentials, public_headers)?;
        let mut response = self
            .inner
            .execute(request)
            .await
            .map_err(|_| HttpClientError::Transport)?;
        let status = response.status().as_u16();
        let mut body =
            BoundedBody::preflight(self.policy.max_body_bytes, response.content_length())
                .map_err(HttpClientError::BodyLimit)?;
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|_| HttpClientError::Transport)?
        {
            body.push(&chunk).map_err(HttpClientError::BodyLimit)?;
        }
        Ok(BoundedResponse {
            status,
            body: body.into_inner(),
        })
    }

    fn prepare_get(
        &self,
        endpoint: &str,
        allowed_hosts: &[&str],
        credentials: CredentialHeaders<'_>,
        public_headers: &[(&str, &str)],
    ) -> Result<Request, HttpClientError> {
        let endpoint = self
            .policy
            .parse_bearer_endpoint(endpoint, allowed_hosts)
            .map_err(HttpClientError::Policy)?;
        let mut request = self.inner.get(endpoint);
        for (name, value) in public_headers {
            let name = HeaderName::from_bytes(name.as_bytes())
                .map_err(|_| HttpClientError::InvalidPublicHeader)?;
            if is_credential_header(&name) || !valid_header_value(value, MAX_PUBLIC_HEADER_BYTES) {
                return Err(HttpClientError::InvalidPublicHeader);
            }
            let value =
                HeaderValue::from_str(value).map_err(|_| HttpClientError::InvalidPublicHeader)?;
            request = request.header(name, value);
        }
        request = match credentials {
            CredentialHeaders::None => request,
            CredentialHeaders::Bearer(bearer) => {
                request.header(AUTHORIZATION, bearer_header(bearer)?)
            }
            CredentialHeaders::BearerWithApiKey { bearer, api_key } => request
                .header(AUTHORIZATION, bearer_header(bearer)?)
                .header("apikey", secret_header(api_key)?),
        };
        request.build().map_err(|_| HttpClientError::Build)
    }
}

impl Default for HardenedHttpClient {
    fn default() -> Self {
        Self::new(HttpPolicy::default()).expect("the fleet HTTP default policy is valid")
    }
}

/// Maps one numeric HTTP status without retaining upstream response text.
#[must_use]
pub fn classify_status(status: u16) -> UpstreamHttpState {
    match StatusCode::from_u16(status) {
        Ok(value) if value.is_success() => UpstreamHttpState::Ready,
        Ok(StatusCode::UNAUTHORIZED) => UpstreamHttpState::Unauthorized,
        Ok(StatusCode::FORBIDDEN) => UpstreamHttpState::Forbidden,
        Ok(_) | Err(_) => UpstreamHttpState::Degraded,
    }
}

fn is_credential_header(name: &HeaderName) -> bool {
    name == AUTHORIZATION
        || name == PROXY_AUTHORIZATION
        || name == COOKIE
        || name == SET_COOKIE
        || name.as_str().eq_ignore_ascii_case("apikey")
        || name.as_str().eq_ignore_ascii_case("x-api-key")
}

fn bearer_header(token: &str) -> Result<HeaderValue, HttpClientError> {
    if !valid_credential(token) {
        return Err(HttpClientError::InvalidCredential);
    }
    let mut header = HeaderValue::from_str(&format!("Bearer {token}"))
        .map_err(|_| HttpClientError::InvalidCredential)?;
    header.set_sensitive(true);
    Ok(header)
}

fn secret_header(secret: &str) -> Result<HeaderValue, HttpClientError> {
    if !valid_credential(secret) {
        return Err(HttpClientError::InvalidCredential);
    }
    let mut header =
        HeaderValue::from_str(secret).map_err(|_| HttpClientError::InvalidCredential)?;
    header.set_sensitive(true);
    Ok(header)
}

fn valid_credential(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_CREDENTIAL_BYTES
        && value.bytes().all(|byte| matches!(byte, 0x21..=0x7e))
}

/// Value-free client failure suitable for conversion to bounded MCP results.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HttpClientError {
    /// URL or exact-host validation failed.
    Policy(HttpPolicyError),
    /// Redirects, deadlines, or response limits were unsafe.
    InvalidPolicy,
    /// A public header was malformed or tried to carry credentials.
    InvalidPublicHeader,
    /// A credential was empty, oversized, or not a printable token.
    InvalidCredential,
    /// The concrete HTTP client or request could not be built.
    Build,
    /// DNS, connection, TLS, timeout, or response streaming failed.
    Transport,
    /// The declared or streamed response exceeded the configured bound.
    BodyLimit(BodyLimitError),
}

impl fmt::Display for HttpClientError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Policy(_) => formatter.write_str("HTTP endpoint rejected by policy"),
            Self::InvalidPolicy => formatter.write_str("invalid hardened HTTP client policy"),
            Self::InvalidPublicHeader => formatter.write_str("invalid public HTTP header"),
            Self::InvalidCredential => formatter.write_str("invalid HTTP credential"),
            Self::Build => formatter.write_str("HTTP client construction failed"),
            Self::Transport => formatter.write_str("HTTP request failed"),
            Self::BodyLimit(_) => formatter.write_str("HTTP response exceeded its byte limit"),
        }
    }
}

impl Error for HttpClientError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::BodyLimit(error) => Some(error),
            Self::Policy(_)
            | Self::InvalidPolicy
            | Self::InvalidPublicHeader
            | Self::InvalidCredential
            | Self::Build
            | Self::Transport => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn statuses_use_the_five_state_contract_subset() {
        assert_eq!(classify_status(200), UpstreamHttpState::Ready);
        assert_eq!(classify_status(204), UpstreamHttpState::Ready);
        assert_eq!(classify_status(401), UpstreamHttpState::Unauthorized);
        assert_eq!(classify_status(403), UpstreamHttpState::Forbidden);
        assert_eq!(classify_status(404), UpstreamHttpState::Degraded);
        assert_eq!(classify_status(503), UpstreamHttpState::Degraded);
        assert_eq!(classify_status(999), UpstreamHttpState::Degraded);
    }

    #[test]
    fn credentialed_request_is_exact_host_and_secret_header_safe() {
        let client = HardenedHttpClient::default();
        let request = client
            .prepare_get(
                "https://api.github.com/orgs/ORESoftware",
                &["api.github.com"],
                CredentialHeaders::Bearer("test-token"),
                &[("accept", "application/vnd.github+json")],
            )
            .expect("safe request");
        let authorization = request
            .headers()
            .get(AUTHORIZATION)
            .expect("authorization header");
        assert!(authorization.is_sensitive());
        assert_eq!(request.url().host_str(), Some("api.github.com"));
        assert_eq!(request.method(), reqwest::Method::GET);

        assert!(matches!(
            client.prepare_get(
                "https://api.github.com.attacker.test/orgs/ORESoftware",
                &["api.github.com"],
                CredentialHeaders::Bearer("test-token"),
                &[],
            ),
            Err(HttpClientError::Policy(HttpPolicyError::HostNotAllowed))
        ));
    }

    #[test]
    fn public_headers_cannot_bypass_credential_handling() {
        let client = HardenedHttpClient::default();
        for name in ["authorization", "proxy-authorization", "cookie", "apikey"] {
            assert!(matches!(
                client.prepare_get(
                    "https://api.example.test/read",
                    &["api.example.test"],
                    CredentialHeaders::None,
                    &[(name, "not-public")],
                ),
                Err(HttpClientError::InvalidPublicHeader)
            ));
        }
        assert!(matches!(
            client.prepare_get(
                "https://api.example.test/read",
                &["api.example.test"],
                CredentialHeaders::Bearer("bad token"),
                &[],
            ),
            Err(HttpClientError::InvalidCredential)
        ));
    }

    #[test]
    fn client_rejects_redirects_and_unbounded_deadlines() {
        let policy = HttpPolicy {
            follow_redirects: true,
            ..HttpPolicy::default()
        };
        assert!(matches!(
            HardenedHttpClient::new(policy),
            Err(HttpClientError::InvalidPolicy)
        ));

        let policy = HttpPolicy {
            timeout_ms: 60_001,
            ..HttpPolicy::default()
        };
        assert!(matches!(
            HardenedHttpClient::new(policy),
            Err(HttpClientError::InvalidPolicy)
        ));
    }
}
