use std::{collections::BTreeSet, error::Error, fmt};

use url::Url;

const MIN_BODY_BYTES: usize = 1024;
const MAX_BODY_BYTES: usize = 1024 * 1024;
const DEFAULT_REQUEST_BODY_BYTES: usize = 256 * 1024;
const DEFAULT_RESPONSE_BODY_BYTES: usize = 1024 * 1024;
const DEFAULT_MAX_SESSIONS: usize = 10_000;

/// Authentication-assurance floor enforced for a remote MCP caller.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum AssuranceLevel {
    /// One verified factor or equivalent baseline authentication.
    Aal1,
    /// Multi-factor or another Shared Auth level-two ceremony.
    Aal2,
    /// Hardware-backed or another Shared Auth level-three ceremony.
    Aal3,
}

impl AssuranceLevel {
    /// Returns the numeric Shared Auth assurance level.
    #[must_use]
    pub const fn number(self) -> u8 {
        match self {
            Self::Aal1 => 1,
            Self::Aal2 => 2,
            Self::Aal3 => 3,
        }
    }
}

/// Exact Shared Auth claim that carries the product/customer realm.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RealmClaim {
    /// The canonical `realm` claim.
    Realm,
    /// The established Shared Auth product `project` claim.
    Project,
    /// A product authority's canonical `tenant_id` claim.
    TenantId,
}

/// Validated, non-secret Shared Auth policy for one remote MCP resource.
#[derive(Clone)]
pub struct RemoteAuthPolicy {
    resource: Url,
    issuer: Url,
    jwks_url: Url,
    resource_metadata_url: Url,
    authorized_clients: BTreeSet<String>,
    realm_claim: RealmClaim,
    realm: String,
    minimum_assurance: AssuranceLevel,
    required_scopes: BTreeSet<String>,
    any_role: BTreeSet<String>,
}

impl fmt::Debug for RemoteAuthPolicy {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RemoteAuthPolicy")
            .field("resource", &self.resource.as_str())
            .field("issuer", &self.issuer.as_str())
            .field("jwks_url", &self.jwks_url.as_str())
            .field("authorized_clients", &self.authorized_clients)
            .field("realm_claim", &self.realm_claim)
            .field("realm", &self.realm)
            .field("minimum_assurance", &self.minimum_assurance)
            .field("required_scopes", &self.required_scopes)
            .field("any_role", &self.any_role)
            .finish()
    }
}

impl RemoteAuthPolicy {
    /// Constructs a fail-closed policy for one exact HTTPS `/mcp` resource.
    ///
    /// The audience is the complete `resource` URL. Shared Auth's issuer and
    /// JWKS endpoint must be HTTPS and share one exact host. At least one OAuth
    /// client, product scope, and product role are required so a valid signature
    /// never silently becomes product authorization.
    ///
    /// # Errors
    ///
    /// Returns a value-free validation error for malformed or incomplete
    /// non-secret policy.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        resource: &str,
        issuer: &str,
        jwks_url: &str,
        authorized_clients: impl IntoIterator<Item = impl Into<String>>,
        realm_claim: RealmClaim,
        realm: impl Into<String>,
        minimum_assurance: AssuranceLevel,
        required_scopes: impl IntoIterator<Item = impl Into<String>>,
        any_role: impl IntoIterator<Item = impl Into<String>>,
    ) -> Result<Self, RemoteConfigError> {
        let resource = parse_https_url(resource, UrlKind::Resource)?;
        if resource.path() != "/mcp" {
            return Err(RemoteConfigError::InvalidResource);
        }
        let issuer = parse_https_url(issuer, UrlKind::Issuer)?;
        let jwks_url = parse_https_url(jwks_url, UrlKind::Jwks)?;
        if normalized_host(&issuer) != normalized_host(&jwks_url) {
            return Err(RemoteConfigError::AuthorityHostMismatch);
        }

        let authorized_clients = validated_set(
            authorized_clients,
            128,
            512,
            RemoteConfigError::InvalidAuthorizedClients,
        )?;
        let required_scopes = validated_set(
            required_scopes,
            64,
            160,
            RemoteConfigError::InvalidRequiredScopes,
        )?;
        let any_role = validated_set(any_role, 64, 160, RemoteConfigError::InvalidRoles)?;
        let realm = realm.into();
        if !valid_token(&realm, 200) {
            return Err(RemoteConfigError::InvalidRealm);
        }

        let mut resource_metadata_url = resource.clone();
        resource_metadata_url.set_path("/.well-known/oauth-protected-resource/mcp");
        resource_metadata_url.set_query(None);
        resource_metadata_url.set_fragment(None);

        Ok(Self {
            resource,
            issuer,
            jwks_url,
            resource_metadata_url,
            authorized_clients,
            realm_claim,
            realm,
            minimum_assurance,
            required_scopes,
            any_role,
        })
    }

    /// Exact RFC 8707 resource identifier and token audience.
    #[must_use]
    pub fn resource(&self) -> &str {
        self.resource.as_str()
    }

    /// Exact Shared Auth issuer.
    #[must_use]
    pub fn issuer(&self) -> &str {
        let serialized = self.issuer.as_str();
        if self.issuer.path() == "/" {
            serialized.trim_end_matches('/')
        } else {
            serialized
        }
    }

    /// Exact bounded JWKS endpoint.
    #[must_use]
    pub fn jwks_url(&self) -> &str {
        self.jwks_url.as_str()
    }

    /// Exact RFC 9728 metadata URL advertised in bearer challenges.
    #[must_use]
    pub fn resource_metadata_url(&self) -> &str {
        self.resource_metadata_url.as_str()
    }

    /// Exact Shared Auth/JWKS host used by the hardened fetcher.
    #[must_use]
    pub fn authority_host(&self) -> &str {
        self.jwks_url
            .host_str()
            .expect("validated JWKS URL always has a host")
    }

    /// OAuth client IDs allowed to invoke this MCP resource.
    #[must_use]
    pub const fn authorized_clients(&self) -> &BTreeSet<String> {
        &self.authorized_clients
    }

    /// Claim carrying the realm boundary.
    #[must_use]
    pub const fn realm_claim(&self) -> RealmClaim {
        self.realm_claim
    }

    /// Exact product/customer realm.
    #[must_use]
    pub fn realm(&self) -> &str {
        &self.realm
    }

    /// Required authentication-assurance floor.
    #[must_use]
    pub const fn minimum_assurance(&self) -> AssuranceLevel {
        self.minimum_assurance
    }

    /// Product scopes required on every remote request.
    #[must_use]
    pub const fn required_scopes(&self) -> &BTreeSet<String> {
        &self.required_scopes
    }

    /// Product roles, at least one of which must be held.
    #[must_use]
    pub const fn any_role(&self) -> &BTreeSet<String> {
        &self.any_role
    }
}

/// Complete non-secret Streamable HTTP posture for one server.
#[derive(Clone, Debug)]
pub struct RemoteMcpConfig {
    auth: RemoteAuthPolicy,
    allowed_hosts: Vec<String>,
    allowed_origins: Vec<String>,
    request_body_max_bytes: usize,
    response_body_max_bytes: usize,
    stateful: bool,
    max_sessions: usize,
}

impl RemoteMcpConfig {
    /// Constructs a stateful remote configuration with fleet body ceilings.
    ///
    /// `allowed_hosts` must include the resource URL's exact authority. Origins
    /// must be exact HTTPS origins without credentials, paths, query, fragments,
    /// wildcards, or templates. Requests without an `Origin` remain valid for
    /// server-to-server clients.
    ///
    /// # Errors
    ///
    /// Returns a value-free error when the inbound authority/origin policy is
    /// empty, unsafe, duplicated, or inconsistent with the protected resource.
    pub fn new(
        auth: RemoteAuthPolicy,
        allowed_hosts: impl IntoIterator<Item = impl Into<String>>,
        allowed_origins: impl IntoIterator<Item = impl Into<String>>,
    ) -> Result<Self, RemoteConfigError> {
        let allowed_hosts = validate_hosts(auth.resource(), allowed_hosts)?;
        let allowed_origins = validate_origins(allowed_origins)?;
        Ok(Self {
            auth,
            allowed_hosts,
            allowed_origins,
            request_body_max_bytes: DEFAULT_REQUEST_BODY_BYTES,
            response_body_max_bytes: DEFAULT_RESPONSE_BODY_BYTES,
            stateful: true,
            max_sessions: DEFAULT_MAX_SESSIONS,
        })
    }

    /// Selects stateful sessions or stateless direct JSON responses.
    #[must_use]
    pub const fn with_stateful_mode(mut self, stateful: bool) -> Self {
        self.stateful = stateful;
        self
    }

    /// Replaces the inbound request and product-result byte ceilings.
    ///
    /// # Errors
    ///
    /// Both limits must be between 1 KiB and 1 MiB inclusive.
    pub fn with_body_limits(
        mut self,
        request_body_max_bytes: usize,
        response_body_max_bytes: usize,
    ) -> Result<Self, RemoteConfigError> {
        if !(MIN_BODY_BYTES..=MAX_BODY_BYTES).contains(&request_body_max_bytes)
            || !(MIN_BODY_BYTES..=MAX_BODY_BYTES).contains(&response_body_max_bytes)
        {
            return Err(RemoteConfigError::InvalidBodyLimit);
        }
        self.request_body_max_bytes = request_body_max_bytes;
        self.response_body_max_bytes = response_body_max_bytes;
        Ok(self)
    }

    /// Bounds the in-memory identity-to-MCP-session binding table.
    ///
    /// # Errors
    ///
    /// Returns an error for zero or more than 100,000 concurrent sessions.
    pub fn with_max_sessions(mut self, maximum: usize) -> Result<Self, RemoteConfigError> {
        if !(1..=100_000).contains(&maximum) {
            return Err(RemoteConfigError::InvalidSessionLimit);
        }
        self.max_sessions = maximum;
        Ok(self)
    }

    /// Validated Shared Auth policy.
    #[must_use]
    pub const fn auth(&self) -> &RemoteAuthPolicy {
        &self.auth
    }

    /// Exact inbound Host authorities passed to `rmcp`.
    #[must_use]
    pub fn allowed_hosts(&self) -> &[String] {
        &self.allowed_hosts
    }

    /// Exact browser origins passed to `rmcp`.
    #[must_use]
    pub fn allowed_origins(&self) -> &[String] {
        &self.allowed_origins
    }

    /// Maximum inbound JSON request bytes, enforced before buffering.
    #[must_use]
    pub const fn request_body_max_bytes(&self) -> usize {
        self.request_body_max_bytes
    }

    /// Maximum serialized product tool result bytes consumers must enforce.
    #[must_use]
    pub const fn response_body_max_bytes(&self) -> usize {
        self.response_body_max_bytes
    }

    /// Whether `rmcp` creates and retains MCP sessions.
    #[must_use]
    pub const fn stateful(&self) -> bool {
        self.stateful
    }

    /// Maximum identity-bound MCP sessions retained by the auth middleware.
    #[must_use]
    pub const fn max_sessions(&self) -> usize {
        self.max_sessions
    }
}

/// Verified identity made available to organization-specific MCP tools.
#[derive(Clone, Eq, PartialEq)]
pub struct RemotePrincipal {
    pub(crate) subject: String,
    pub(crate) session_id: String,
    pub(crate) authorized_client: String,
    pub(crate) realm: String,
    pub(crate) assurance: AssuranceLevel,
    pub(crate) authentication_methods: BTreeSet<String>,
    pub(crate) roles: BTreeSet<String>,
    pub(crate) scopes: BTreeSet<String>,
}

impl fmt::Debug for RemotePrincipal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RemotePrincipal")
            .field("subject", &"[redacted]")
            .field("session_id", &"[redacted]")
            .field("authorized_client", &self.authorized_client)
            .field("realm", &self.realm)
            .field("assurance", &self.assurance)
            .field("authentication_methods", &self.authentication_methods)
            .field("roles", &self.roles)
            .field("scopes", &self.scopes)
            .finish()
    }
}

impl RemotePrincipal {
    /// Stable Shared Auth subject identifier.
    #[must_use]
    pub fn subject(&self) -> &str {
        &self.subject
    }

    /// Bound Shared Auth browser or workload session identifier.
    #[must_use]
    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    /// OAuth client ID proven by `azp`/`client_id`.
    #[must_use]
    pub fn authorized_client(&self) -> &str {
        &self.authorized_client
    }

    /// Exact product/customer realm.
    #[must_use]
    pub fn realm(&self) -> &str {
        &self.realm
    }

    /// Proven authentication assurance.
    #[must_use]
    pub const fn assurance(&self) -> AssuranceLevel {
        self.assurance
    }

    /// Authentication methods recorded by Shared Auth.
    #[must_use]
    pub const fn authentication_methods(&self) -> &BTreeSet<String> {
        &self.authentication_methods
    }

    /// Product roles recorded by Shared Auth.
    #[must_use]
    pub const fn roles(&self) -> &BTreeSet<String> {
        &self.roles
    }

    /// Product scopes recorded by Shared Auth.
    #[must_use]
    pub const fn scopes(&self) -> &BTreeSet<String> {
        &self.scopes
    }
}

/// Value-free remote policy validation failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RemoteConfigError {
    /// The protected resource was not an exact HTTPS `/mcp` URL.
    InvalidResource,
    /// The Shared Auth issuer was not a bounded HTTPS URL.
    InvalidIssuer,
    /// The Shared Auth JWKS endpoint was not a bounded HTTPS URL.
    InvalidJwksUrl,
    /// Issuer and JWKS hosts differed.
    AuthorityHostMismatch,
    /// No bounded, unique OAuth client allowlist was supplied.
    InvalidAuthorizedClients,
    /// The realm was missing or malformed.
    InvalidRealm,
    /// Required scopes were missing, duplicated, or malformed.
    InvalidRequiredScopes,
    /// Product roles were missing, duplicated, or malformed.
    InvalidRoles,
    /// Inbound Host authorities were missing, unsafe, or excluded the resource.
    InvalidAllowedHosts,
    /// Browser origins were missing, non-HTTPS, wildcarded, or non-origin URLs.
    InvalidAllowedOrigins,
    /// A request or response ceiling fell outside the fleet range.
    InvalidBodyLimit,
    /// The stateful session-table bound was unsafe.
    InvalidSessionLimit,
}

impl fmt::Display for RemoteConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidResource => "invalid remote MCP resource",
            Self::InvalidIssuer => "invalid Shared Auth issuer",
            Self::InvalidJwksUrl => "invalid Shared Auth JWKS URL",
            Self::AuthorityHostMismatch => "Shared Auth issuer and JWKS host mismatch",
            Self::InvalidAuthorizedClients => "invalid authorized OAuth clients",
            Self::InvalidRealm => "invalid Shared Auth realm",
            Self::InvalidRequiredScopes => "invalid required Shared Auth scopes",
            Self::InvalidRoles => "invalid Shared Auth roles",
            Self::InvalidAllowedHosts => "invalid remote MCP Host allowlist",
            Self::InvalidAllowedOrigins => "invalid remote MCP Origin allowlist",
            Self::InvalidBodyLimit => "invalid remote MCP body limit",
            Self::InvalidSessionLimit => "invalid remote MCP session limit",
        })
    }
}

impl Error for RemoteConfigError {}

#[derive(Clone, Copy)]
enum UrlKind {
    Resource,
    Issuer,
    Jwks,
}

fn parse_https_url(value: &str, kind: UrlKind) -> Result<Url, RemoteConfigError> {
    let error = match kind {
        UrlKind::Resource => RemoteConfigError::InvalidResource,
        UrlKind::Issuer => RemoteConfigError::InvalidIssuer,
        UrlKind::Jwks => RemoteConfigError::InvalidJwksUrl,
    };
    if value.is_empty()
        || value.len() > 2048
        || value.chars().any(char::is_whitespace)
        || value.chars().any(char::is_control)
    {
        return Err(error);
    }
    let parsed = Url::parse(value).map_err(|_| error)?;
    if parsed.scheme() != "https"
        || parsed.host().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        return Err(error);
    }
    Ok(parsed)
}

fn normalized_host(url: &Url) -> Option<(String, u16)> {
    Some((
        url.host_str()?.trim_end_matches('.').to_ascii_lowercase(),
        url.port_or_known_default()?,
    ))
}

fn validated_set(
    values: impl IntoIterator<Item = impl Into<String>>,
    maximum_items: usize,
    maximum_bytes: usize,
    error: RemoteConfigError,
) -> Result<BTreeSet<String>, RemoteConfigError> {
    let collected: Vec<String> = values.into_iter().map(Into::into).collect();
    if collected.is_empty() || collected.len() > maximum_items {
        return Err(error);
    }
    let mut result = BTreeSet::new();
    for value in collected {
        if !valid_token(&value, maximum_bytes) || !result.insert(value) {
            return Err(error);
        }
    }
    Ok(result)
}

fn valid_token(value: &str, maximum_bytes: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum_bytes
        && value
            .bytes()
            .all(|byte| byte.is_ascii_graphic() && !matches!(byte, b',' | b'"' | b'\''))
}

fn validate_hosts(
    resource: &str,
    values: impl IntoIterator<Item = impl Into<String>>,
) -> Result<Vec<String>, RemoteConfigError> {
    let resource = Url::parse(resource).map_err(|_| RemoteConfigError::InvalidAllowedHosts)?;
    let expected = normalized_host(&resource).ok_or(RemoteConfigError::InvalidAllowedHosts)?;
    let collected: Vec<String> = values.into_iter().map(Into::into).collect();
    if collected.is_empty() || collected.len() > 64 {
        return Err(RemoteConfigError::InvalidAllowedHosts);
    }
    let mut seen = BTreeSet::new();
    let mut includes_resource = false;
    for value in &collected {
        if value.is_empty()
            || value.len() > 320
            || value.contains('*')
            || value.contains('{')
            || value.contains('}')
            || value.chars().any(char::is_whitespace)
        {
            return Err(RemoteConfigError::InvalidAllowedHosts);
        }
        let candidate = Url::parse(&format!("https://{value}/"))
            .map_err(|_| RemoteConfigError::InvalidAllowedHosts)?;
        if candidate.host().is_none()
            || !candidate.username().is_empty()
            || candidate.password().is_some()
            || candidate.path() != "/"
            || candidate.query().is_some()
            || candidate.fragment().is_some()
        {
            return Err(RemoteConfigError::InvalidAllowedHosts);
        }
        let normalized =
            normalized_host(&candidate).ok_or(RemoteConfigError::InvalidAllowedHosts)?;
        if !seen.insert(normalized.clone()) {
            return Err(RemoteConfigError::InvalidAllowedHosts);
        }
        includes_resource |= normalized == expected;
    }
    if !includes_resource {
        return Err(RemoteConfigError::InvalidAllowedHosts);
    }
    Ok(collected)
}

fn validate_origins(
    values: impl IntoIterator<Item = impl Into<String>>,
) -> Result<Vec<String>, RemoteConfigError> {
    let collected: Vec<String> = values.into_iter().map(Into::into).collect();
    if collected.is_empty() || collected.len() > 64 {
        return Err(RemoteConfigError::InvalidAllowedOrigins);
    }
    let mut seen = BTreeSet::new();
    for value in &collected {
        if value.contains('*') || value.contains('{') || value.contains('}') {
            return Err(RemoteConfigError::InvalidAllowedOrigins);
        }
        let origin = parse_https_url(value, UrlKind::Resource)
            .map_err(|_| RemoteConfigError::InvalidAllowedOrigins)?;
        if origin.path() != "/" || !seen.insert(origin.origin().ascii_serialization()) {
            return Err(RemoteConfigError::InvalidAllowedOrigins);
        }
    }
    Ok(collected)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> RemoteAuthPolicy {
        RemoteAuthPolicy::new(
            "https://mcp.example.test/mcp",
            "https://auth.example.test",
            "https://auth.example.test/.well-known/jwks.json",
            ["cursor-client", "openai-client"],
            RealmClaim::Project,
            "example",
            AssuranceLevel::Aal2,
            ["mcp:read"],
            ["member", "operator"],
        )
        .expect("valid policy")
    }

    #[test]
    fn policy_binds_resource_authority_client_realm_and_assurance() {
        let policy = policy();
        assert_eq!(policy.resource(), "https://mcp.example.test/mcp");
        assert_eq!(policy.issuer(), "https://auth.example.test");
        assert_eq!(policy.authority_host(), "auth.example.test");
        assert_eq!(policy.realm_claim(), RealmClaim::Project);
        assert_eq!(policy.realm(), "example");
        assert_eq!(policy.minimum_assurance(), AssuranceLevel::Aal2);
        assert_eq!(
            policy.resource_metadata_url(),
            "https://mcp.example.test/.well-known/oauth-protected-resource/mcp"
        );

        let principal = RemotePrincipal {
            subject: "private-subject".into(),
            session_id: "private-session".into(),
            authorized_client: "cursor-client".into(),
            realm: "example".into(),
            assurance: AssuranceLevel::Aal2,
            authentication_methods: BTreeSet::from(["passkey".into()]),
            roles: BTreeSet::from(["member".into()]),
            scopes: BTreeSet::from(["mcp:read".into()]),
        };
        let rendered = format!("{principal:?}");
        assert!(!rendered.contains("private-subject"));
        assert!(!rendered.contains("private-session"));
    }

    #[test]
    fn policy_requires_exact_https_resource_and_authority_host() {
        for resource in [
            "http://mcp.example.test/mcp",
            "https://user:password@mcp.example.test/mcp",
            "https://mcp.example.test/other",
            "https://mcp.example.test/mcp?tenant=one",
        ] {
            assert!(matches!(
                RemoteAuthPolicy::new(
                    resource,
                    "https://auth.example.test",
                    "https://auth.example.test/.well-known/jwks.json",
                    ["client"],
                    RealmClaim::Realm,
                    "example",
                    AssuranceLevel::Aal1,
                    ["mcp:read"],
                    ["member"],
                ),
                Err(RemoteConfigError::InvalidResource)
            ));
        }
        assert!(matches!(
            RemoteAuthPolicy::new(
                "https://mcp.example.test/mcp",
                "https://auth.example.test",
                "https://evil.example.test/.well-known/jwks.json",
                ["client"],
                RealmClaim::Realm,
                "example",
                AssuranceLevel::Aal1,
                ["mcp:read"],
                ["member"],
            ),
            Err(RemoteConfigError::AuthorityHostMismatch)
        ));

        let path_issuer = RemoteAuthPolicy::new(
            "https://mcp.example.test/mcp",
            "https://auth.example.test/realms/example/",
            "https://auth.example.test/.well-known/jwks.json",
            ["client"],
            RealmClaim::Realm,
            "example",
            AssuranceLevel::Aal1,
            ["mcp:read"],
            ["member"],
        )
        .expect("path issuer");
        assert_eq!(
            path_issuer.issuer(),
            "https://auth.example.test/realms/example/"
        );
    }

    #[test]
    fn product_authorization_collections_cannot_be_empty_or_duplicated() {
        assert!(matches!(
            RemoteAuthPolicy::new(
                "https://mcp.example.test/mcp",
                "https://auth.example.test",
                "https://auth.example.test/.well-known/jwks.json",
                ["client", "client"],
                RealmClaim::Realm,
                "example",
                AssuranceLevel::Aal1,
                ["mcp:read"],
                ["member"],
            ),
            Err(RemoteConfigError::InvalidAuthorizedClients)
        ));
        assert!(matches!(
            RemoteAuthPolicy::new(
                "https://mcp.example.test/mcp",
                "https://auth.example.test",
                "https://auth.example.test/.well-known/jwks.json",
                ["client"],
                RealmClaim::Realm,
                "example",
                AssuranceLevel::Aal1,
                Vec::<String>::new(),
                ["member"],
            ),
            Err(RemoteConfigError::InvalidRequiredScopes)
        ));
    }

    #[test]
    fn transport_config_requires_exact_resource_host_and_origins() {
        let config =
            RemoteMcpConfig::new(policy(), ["mcp.example.test"], ["https://app.example.test"])
                .expect("valid config");
        assert_eq!(config.allowed_hosts(), ["mcp.example.test"]);
        assert_eq!(config.allowed_origins(), ["https://app.example.test"]);
        assert!(config.stateful());

        assert!(matches!(
            RemoteMcpConfig::new(
                policy(),
                ["mcp.example.test.attacker.test"],
                ["https://app.example.test"],
            ),
            Err(RemoteConfigError::InvalidAllowedHosts)
        ));
        for origin in [
            "http://app.example.test",
            "https://*.example.test",
            "https://app.example.test/path",
        ] {
            assert!(matches!(
                RemoteMcpConfig::new(policy(), ["mcp.example.test"], [origin]),
                Err(RemoteConfigError::InvalidAllowedOrigins)
            ));
        }
    }

    #[test]
    fn body_and_session_bounds_fail_closed() {
        let config =
            RemoteMcpConfig::new(policy(), ["mcp.example.test"], ["https://app.example.test"])
                .expect("valid config");
        assert!(matches!(
            config.clone().with_body_limits(1023, 4096),
            Err(RemoteConfigError::InvalidBodyLimit)
        ));
        assert!(matches!(
            config.clone().with_body_limits(4096, 1024 * 1024 + 1),
            Err(RemoteConfigError::InvalidBodyLimit)
        ));
        assert!(matches!(
            config.with_max_sessions(0),
            Err(RemoteConfigError::InvalidSessionLimit)
        ));
    }
}
