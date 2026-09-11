use std::{
    collections::BTreeSet,
    error::Error,
    fmt,
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use jsonwebtoken::{
    decode, decode_header,
    jwk::{AlgorithmParameters, EllipticCurve, JwkSet, KeyAlgorithm, PublicKeyUse},
    Algorithm, DecodingKey, Validation,
};
use ore_mcp_http::{CredentialHeaders, HardenedHttpClient, HttpPolicy};
use serde::Deserialize;
use tokio::sync::{Mutex, RwLock};

use crate::{AssuranceLevel, RemoteAuthPolicy, RemotePrincipal};

const MAX_ACCESS_TOKEN_BYTES: usize = 16 * 1024;
const MAX_JWKS_BYTES: usize = 256 * 1024;
const MAX_JWKS_KEYS: usize = 64;
const MAX_CLAIM_ITEMS: usize = 128;
const CLOCK_SKEW_SECONDS: u64 = 15;
const DEFAULT_JWKS_TTL: Duration = Duration::from_secs(10 * 60);
const DEFAULT_JWKS_GRACE: Duration = Duration::from_secs(60 * 60);
const REFRESH_BACKOFF: Duration = Duration::from_secs(30);

/// Stable authorization failure mapped to a bounded HTTP response.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthorizationFailure {
    /// No single well-formed bearer credential was supplied.
    MissingCredential,
    /// The credential was malformed, expired, or invalid for this resource.
    InvalidCredential,
    /// Authentication succeeded but product/client policy denied access.
    Forbidden,
    /// Shared Auth keys were unavailable, so the server could not decide.
    AuthorityUnavailable,
    /// The bounded stateful-session identity table could not accept a session.
    SessionCapacity,
}

impl AuthorizationFailure {
    /// Stable, low-cardinality failure label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::MissingCredential => "missing_credential",
            Self::InvalidCredential => "invalid_credential",
            Self::Forbidden => "forbidden",
            Self::AuthorityUnavailable => "authority_unavailable",
            Self::SessionCapacity => "session_capacity",
        }
    }
}

impl fmt::Display for AuthorizationFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl Error for AuthorizationFailure {}

/// Readiness of the local Shared Auth JWKS verification path.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VerifierReadiness {
    /// A static or fresh key set is available.
    Ready,
    /// A stale-but-within-grace key set can still verify known keys.
    Grace,
    /// No safe key set is available.
    Unavailable,
}

impl VerifierReadiness {
    /// Stable health label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ready => "ready",
            Self::Grace => "grace",
            Self::Unavailable => "unavailable",
        }
    }
}

#[derive(Clone)]
struct CachedJwks {
    keys: Arc<JwkSet>,
    fetched_at: Instant,
    immutable: bool,
}

/// Local Shared Auth ES256 verifier with bounded, exact-host JWKS refresh.
#[derive(Clone)]
pub struct SharedAuthVerifier {
    policy: RemoteAuthPolicy,
    http: HardenedHttpClient,
    cache: Arc<RwLock<Option<CachedJwks>>>,
    refresh: Arc<Mutex<Option<Instant>>>,
    jwks_ttl: Duration,
    jwks_grace: Duration,
}

impl SharedAuthVerifier {
    /// Constructs a verifier whose JWKS requests deny redirects and ambient
    /// proxies, use the issuer's exact host, enforce a five-second deadline,
    /// and stop buffering at 256 KiB.
    ///
    /// # Errors
    ///
    /// Returns a value-free authority-unavailable failure only if the static
    /// hardened HTTP policy cannot be constructed.
    pub fn new(policy: RemoteAuthPolicy) -> Result<Self, AuthorizationFailure> {
        let http = HardenedHttpClient::new(HttpPolicy {
            timeout_ms: 5_000,
            max_body_bytes: MAX_JWKS_BYTES,
            allow_loopback_http: false,
            follow_redirects: false,
        })
        .map_err(|_| AuthorizationFailure::AuthorityUnavailable)?;
        Ok(Self {
            policy,
            http,
            cache: Arc::new(RwLock::new(None)),
            refresh: Arc::new(Mutex::new(None)),
            jwks_ttl: DEFAULT_JWKS_TTL,
            jwks_grace: DEFAULT_JWKS_GRACE,
        })
    }

    /// Constructs an offline verifier from a bounded static JWKS document.
    ///
    /// Static keys never trigger network access and remain ready until the
    /// process replaces the verifier.
    ///
    /// # Errors
    ///
    /// Returns a value-free failure for malformed, empty, duplicated, non-P-256,
    /// non-signature, or non-ES256 keys.
    pub fn with_static_jwks_json(
        policy: RemoteAuthPolicy,
        document: &[u8],
    ) -> Result<Self, AuthorizationFailure> {
        if document.len() > MAX_JWKS_BYTES {
            return Err(AuthorizationFailure::AuthorityUnavailable);
        }
        let keys = parse_jwks(document)?;
        let mut verifier = Self::new(policy)?;
        verifier.cache = Arc::new(RwLock::new(Some(CachedJwks {
            keys: Arc::new(keys),
            fetched_at: Instant::now(),
            immutable: true,
        })));
        Ok(verifier)
    }

    /// Returns the immutable, non-secret policy.
    #[must_use]
    pub const fn policy(&self) -> &RemoteAuthPolicy {
        &self.policy
    }

    /// Fetches and validates Shared Auth keys before the first MCP request.
    ///
    /// # Errors
    ///
    /// Returns authority unavailable without retaining upstream response text.
    pub async fn warm(&self) -> Result<(), AuthorizationFailure> {
        self.refresh_keys(true).await.map(|_| ())
    }

    /// Reports whether local verification can currently make a decision.
    pub async fn readiness(&self) -> VerifierReadiness {
        let cache = self.cache.read().await;
        let Some(cached) = cache.as_ref() else {
            return VerifierReadiness::Unavailable;
        };
        if cached.immutable || cached.fetched_at.elapsed() <= self.jwks_ttl {
            VerifierReadiness::Ready
        } else if cached.fetched_at.elapsed() <= self.jwks_grace {
            VerifierReadiness::Grace
        } else {
            VerifierReadiness::Unavailable
        }
    }

    /// Verifies one bearer token locally and enforces every product boundary.
    ///
    /// The returned principal contains no access token and is safe to insert
    /// into request extensions. Unknown key IDs trigger one bounded refresh;
    /// when refresh is unavailable the result remains indeterminate rather than
    /// being mislabeled as a bad credential.
    ///
    /// # Errors
    ///
    /// Distinguishes invalid authentication, forbidden product authorization,
    /// and unavailable Shared Auth key material.
    pub async fn verify_bearer(
        &self,
        token: &str,
    ) -> Result<RemotePrincipal, AuthorizationFailure> {
        if !valid_access_token(token) {
            return Err(AuthorizationFailure::InvalidCredential);
        }
        let header = decode_header(token).map_err(|_| AuthorizationFailure::InvalidCredential)?;
        if header.alg != Algorithm::ES256 {
            return Err(AuthorizationFailure::InvalidCredential);
        }
        let key_id = header
            .kid
            .filter(|value| valid_claim_token(value, 200))
            .ok_or(AuthorizationFailure::InvalidCredential)?;

        let current = self.current_keys().await?;
        match verify_with_keys(token, &key_id, &current, &self.policy) {
            KeyVerification::Verified(claims) => authorize_claims(*claims, &self.policy),
            KeyVerification::Invalid => Err(AuthorizationFailure::InvalidCredential),
            KeyVerification::UnknownKey if current.immutable => {
                Err(AuthorizationFailure::InvalidCredential)
            }
            KeyVerification::UnknownKey => {
                let refreshed = self.refresh_keys(true).await?;
                match verify_with_keys(token, &key_id, &refreshed, &self.policy) {
                    KeyVerification::Verified(claims) => authorize_claims(*claims, &self.policy),
                    KeyVerification::Invalid | KeyVerification::UnknownKey => {
                        Err(AuthorizationFailure::InvalidCredential)
                    }
                }
            }
        }
    }

    async fn current_keys(&self) -> Result<Arc<CachedJwks>, AuthorizationFailure> {
        let cached = self.cache.read().await.clone();
        match cached {
            Some(cached) if cached.immutable || cached.fetched_at.elapsed() <= self.jwks_ttl => {
                Ok(Arc::new(cached))
            }
            stale => match self.refresh_keys(false).await {
                Ok(fresh) => Ok(fresh),
                Err(_) => stale
                    .filter(|cached| cached.fetched_at.elapsed() <= self.jwks_grace)
                    .map(Arc::new)
                    .ok_or(AuthorizationFailure::AuthorityUnavailable),
            },
        }
    }

    async fn refresh_keys(&self, force: bool) -> Result<Arc<CachedJwks>, AuthorizationFailure> {
        let mut last_refresh_attempt = self.refresh.lock().await;
        if !force {
            if let Some(cached) = self.cache.read().await.as_ref() {
                if cached.immutable || cached.fetched_at.elapsed() <= self.jwks_ttl {
                    return Ok(Arc::new(cached.clone()));
                }
            }
        }
        if self
            .cache
            .read()
            .await
            .as_ref()
            .is_some_and(|cached| cached.immutable)
        {
            return self
                .cache
                .read()
                .await
                .as_ref()
                .cloned()
                .map(Arc::new)
                .ok_or(AuthorizationFailure::AuthorityUnavailable);
        }
        if last_refresh_attempt.is_some_and(|attempt| attempt.elapsed() < REFRESH_BACKOFF) {
            if force {
                return Err(AuthorizationFailure::AuthorityUnavailable);
            }
            return self
                .cache
                .read()
                .await
                .as_ref()
                .filter(|cached| cached.fetched_at.elapsed() <= self.jwks_grace)
                .cloned()
                .map(Arc::new)
                .ok_or(AuthorizationFailure::AuthorityUnavailable);
        }
        *last_refresh_attempt = Some(Instant::now());

        let response = self
            .http
            .get(
                self.policy.jwks_url(),
                &[self.policy.authority_host()],
                CredentialHeaders::None,
                &[("accept", "application/json")],
            )
            .await
            .map_err(|_| AuthorizationFailure::AuthorityUnavailable)?;
        if response.status() != 200 {
            return Err(AuthorizationFailure::AuthorityUnavailable);
        }
        let keys = parse_jwks(response.body())?;
        let cached = CachedJwks {
            keys: Arc::new(keys),
            fetched_at: Instant::now(),
            immutable: false,
        };
        *self.cache.write().await = Some(cached.clone());
        Ok(Arc::new(cached))
    }
}

fn parse_jwks(document: &[u8]) -> Result<JwkSet, AuthorizationFailure> {
    let set: JwkSet =
        serde_json::from_slice(document).map_err(|_| AuthorizationFailure::AuthorityUnavailable)?;
    if set.keys.is_empty() || set.keys.len() > MAX_JWKS_KEYS {
        return Err(AuthorizationFailure::AuthorityUnavailable);
    }
    let mut key_ids = BTreeSet::new();
    for key in &set.keys {
        let Some(key_id) = key.common.key_id.as_deref() else {
            return Err(AuthorizationFailure::AuthorityUnavailable);
        };
        if !valid_claim_token(key_id, 200) || !key_ids.insert(key_id) {
            return Err(AuthorizationFailure::AuthorityUnavailable);
        }
        if key.common.key_algorithm != Some(KeyAlgorithm::ES256)
            || key
                .common
                .public_key_use
                .as_ref()
                .is_some_and(|usage| usage != &PublicKeyUse::Signature)
            || !matches!(
                &key.algorithm,
                AlgorithmParameters::EllipticCurve(parameters)
                    if parameters.curve == EllipticCurve::P256
            )
        {
            return Err(AuthorizationFailure::AuthorityUnavailable);
        }
        DecodingKey::from_jwk(key).map_err(|_| AuthorizationFailure::AuthorityUnavailable)?;
    }
    Ok(set)
}

enum KeyVerification {
    Verified(Box<SharedAuthClaims>),
    UnknownKey,
    Invalid,
}

fn verify_with_keys(
    token: &str,
    key_id: &str,
    cache: &CachedJwks,
    policy: &RemoteAuthPolicy,
) -> KeyVerification {
    let Some(jwk) = cache.keys.find(key_id) else {
        return KeyVerification::UnknownKey;
    };
    let Ok(key) = DecodingKey::from_jwk(jwk) else {
        return KeyVerification::Invalid;
    };
    let mut validation = Validation::new(Algorithm::ES256);
    validation.leeway = CLOCK_SKEW_SECONDS;
    validation.validate_exp = true;
    validation.validate_nbf = true;
    validation.set_required_spec_claims(&["aud", "exp", "iat", "iss", "nbf", "sub"]);
    validation.set_issuer(&[policy.issuer()]);
    validation.set_audience(&[policy.resource()]);
    match decode::<SharedAuthClaims>(token, &key, &validation) {
        Ok(decoded) => KeyVerification::Verified(Box::new(decoded.claims)),
        Err(_) => KeyVerification::Invalid,
    }
}

#[derive(Deserialize)]
struct SharedAuthClaims {
    sub: String,
    aud: AudienceClaim,
    iat: u64,
    nbf: u64,
    exp: u64,
    #[serde(default)]
    sid: Option<String>,
    #[serde(default)]
    azp: Option<String>,
    #[serde(default)]
    client_id: Option<String>,
    #[serde(default)]
    realm: Option<String>,
    #[serde(default)]
    project: Option<String>,
    #[serde(default)]
    tenant_id: Option<String>,
    #[serde(default)]
    scope: Option<String>,
    #[serde(default)]
    roles: Vec<String>,
    #[serde(default)]
    amr: Vec<String>,
    #[serde(default)]
    acr: Option<String>,
    #[serde(default)]
    aal: Option<AssuranceClaim>,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum AssuranceClaim {
    Number(u8),
    Text(String),
}

#[derive(Deserialize)]
#[serde(untagged)]
enum AudienceClaim {
    One(String),
    Many(Vec<String>),
}

impl AudienceClaim {
    fn is_exact(&self, expected: &str) -> bool {
        match self {
            Self::One(value) => value == expected,
            Self::Many(values) => values.len() == 1 && values[0] == expected,
        }
    }
}

fn authorize_claims(
    claims: SharedAuthClaims,
    policy: &RemoteAuthPolicy,
) -> Result<RemotePrincipal, AuthorizationFailure> {
    if !valid_claim_token(&claims.sub, 200) {
        return Err(AuthorizationFailure::Forbidden);
    }
    if !claims.aud.is_exact(policy.resource())
        || claims.iat > now_seconds().saturating_add(CLOCK_SKEW_SECONDS)
        || claims.iat > claims.exp
        || claims.nbf > claims.exp
    {
        return Err(AuthorizationFailure::InvalidCredential);
    }
    let authorized_client = authorized_client(&claims)?;
    let session_id = claims
        .sid
        .filter(|value| valid_claim_token(value, 200))
        .ok_or(AuthorizationFailure::Forbidden)?;
    if !policy.authorized_clients().contains(&authorized_client) {
        return Err(AuthorizationFailure::Forbidden);
    }
    let realm = match policy.realm_claim() {
        crate::RealmClaim::Realm => claims.realm,
        crate::RealmClaim::Project => claims.project,
        crate::RealmClaim::TenantId => claims.tenant_id,
    }
    .filter(|value| valid_claim_token(value, 200))
    .ok_or(AuthorizationFailure::Forbidden)?;
    if realm != policy.realm() {
        return Err(AuthorizationFailure::Forbidden);
    }

    let assurance = assurance_level(claims.aal.as_ref(), claims.acr.as_deref())
        .ok_or(AuthorizationFailure::Forbidden)?;
    if assurance < policy.minimum_assurance() {
        return Err(AuthorizationFailure::Forbidden);
    }
    let scopes = parse_scope(claims.scope.as_deref())?;
    if !policy.required_scopes().is_subset(&scopes) {
        return Err(AuthorizationFailure::Forbidden);
    }
    let roles = claim_set(claims.roles, 160)?;
    if policy.any_role().is_disjoint(&roles) {
        return Err(AuthorizationFailure::Forbidden);
    }
    let authentication_methods = claim_set(claims.amr, 160)?;

    Ok(RemotePrincipal {
        subject: claims.sub,
        session_id,
        authorized_client,
        realm,
        assurance,
        authentication_methods,
        roles,
        scopes,
    })
}

fn authorized_client(claims: &SharedAuthClaims) -> Result<String, AuthorizationFailure> {
    if claims.azp.is_some() && claims.client_id.is_some() && claims.azp != claims.client_id {
        return Err(AuthorizationFailure::Forbidden);
    }
    claims
        .azp
        .as_ref()
        .or(claims.client_id.as_ref())
        .filter(|value| valid_claim_token(value, 512))
        .cloned()
        .ok_or(AuthorizationFailure::Forbidden)
}

fn assurance_level(aal: Option<&AssuranceClaim>, acr: Option<&str>) -> Option<AssuranceLevel> {
    let from_aal = match aal {
        Some(AssuranceClaim::Number(1)) => Some(AssuranceLevel::Aal1),
        Some(AssuranceClaim::Number(2)) => Some(AssuranceLevel::Aal2),
        Some(AssuranceClaim::Number(3)) => Some(AssuranceLevel::Aal3),
        Some(AssuranceClaim::Text(value)) => match value.as_str() {
            "1" | "aal1" => Some(AssuranceLevel::Aal1),
            "2" | "aal2" => Some(AssuranceLevel::Aal2),
            "3" | "aal3" => Some(AssuranceLevel::Aal3),
            _ => None,
        },
        Some(AssuranceClaim::Number(_)) | None => None,
    };
    let from_acr = match acr {
        Some("urn:oresoftware:loa:1" | "aal1") => Some(AssuranceLevel::Aal1),
        Some("urn:oresoftware:loa:2" | "aal2") => Some(AssuranceLevel::Aal2),
        Some("urn:oresoftware:loa:3" | "aal3") => Some(AssuranceLevel::Aal3),
        Some(_) | None => None,
    };
    match (from_aal, from_acr) {
        (Some(left), Some(right)) if left == right => Some(left),
        (Some(level), None) | (None, Some(level)) => Some(level),
        (Some(_), Some(_)) | (None, None) => None,
    }
}

fn parse_scope(value: Option<&str>) -> Result<BTreeSet<String>, AuthorizationFailure> {
    let value = value.ok_or(AuthorizationFailure::Forbidden)?;
    let items: Vec<String> = value.split_ascii_whitespace().map(str::to_owned).collect();
    claim_set(items, 160)
}

fn claim_set(
    values: Vec<String>,
    maximum_bytes: usize,
) -> Result<BTreeSet<String>, AuthorizationFailure> {
    if values.is_empty() || values.len() > MAX_CLAIM_ITEMS {
        return Err(AuthorizationFailure::Forbidden);
    }
    let mut result = BTreeSet::new();
    for value in values {
        if !valid_claim_token(&value, maximum_bytes) || !result.insert(value) {
            return Err(AuthorizationFailure::Forbidden);
        }
    }
    Ok(result)
}

fn valid_access_token(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_ACCESS_TOKEN_BYTES
        && value.bytes().all(|byte| matches!(byte, 0x21..=0x7e))
        && !value.contains(',')
}

fn valid_claim_token(value: &str, maximum_bytes: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum_bytes
        && value
            .bytes()
            .all(|byte| byte.is_ascii_graphic() && !matches!(byte, b',' | b'"' | b'\''))
}

pub(crate) fn now_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use jsonwebtoken::{encode, EncodingKey, Header};
    use p256::{
        pkcs8::{EncodePrivateKey, LineEnding},
        SecretKey,
    };
    use serde_json::{json, Value};

    use super::*;
    use crate::RealmClaim;

    const KEY_ID: &str = "shared-auth-test-key";

    fn policy() -> RemoteAuthPolicy {
        RemoteAuthPolicy::new(
            "https://mcp.example.test/mcp",
            "https://auth.example.test",
            "https://auth.example.test/.well-known/jwks.json",
            ["cursor-client", "openai-client"],
            RealmClaim::Project,
            "example",
            AssuranceLevel::Aal2,
            ["mcp:read", "example:inspect"],
            ["member", "operator"],
        )
        .expect("valid policy")
    }

    fn secret_key() -> SecretKey {
        SecretKey::from_slice(&[5_u8; 32]).expect("valid deterministic test key")
    }

    fn private_pem() -> String {
        secret_key()
            .to_pkcs8_pem(LineEnding::LF)
            .expect("test key encodes")
            .to_string()
    }

    fn jwks(key_id: &str) -> Vec<u8> {
        let mut jwk = serde_json::to_value(secret_key().public_key().to_jwk())
            .expect("public key serializes");
        let object = jwk.as_object_mut().expect("JWK object");
        object.insert("kid".into(), key_id.into());
        object.insert("alg".into(), "ES256".into());
        object.insert("use".into(), "sig".into());
        serde_json::to_vec(&json!({"keys": [jwk]})).expect("JWKS serializes")
    }

    fn claims() -> Value {
        let now = now_seconds();
        json!({
            "iss": "https://auth.example.test",
            "aud": "https://mcp.example.test/mcp",
            "sub": "shared-user-1",
            "iat": now,
            "nbf": now.saturating_sub(1),
            "exp": now + 600,
            "sid": "session-1",
            "azp": "cursor-client",
            "project": "example",
            "scope": "mcp:read example:inspect",
            "roles": ["member"],
            "amr": ["totp", "passkey"],
            "aal": 2,
            "acr": "urn:oresoftware:loa:2"
        })
    }

    fn token(key_id: &str, claims: &Value) -> String {
        let mut header = Header::new(Algorithm::ES256);
        header.kid = Some(key_id.to_owned());
        encode(
            &header,
            claims,
            &EncodingKey::from_ec_pem(private_pem().as_bytes()).expect("test encoding key"),
        )
        .expect("test token")
    }

    fn verifier() -> SharedAuthVerifier {
        SharedAuthVerifier::with_static_jwks_json(policy(), &jwks(KEY_ID))
            .expect("valid static verifier")
    }

    #[tokio::test]
    async fn verifies_all_required_shared_auth_bindings_offline() {
        let verifier = verifier();
        assert_eq!(verifier.readiness().await, VerifierReadiness::Ready);
        let principal = verifier
            .verify_bearer(&token(KEY_ID, &claims()))
            .await
            .expect("authorized token");
        assert_eq!(principal.subject(), "shared-user-1");
        assert_eq!(principal.session_id(), "session-1");
        assert_eq!(principal.authorized_client(), "cursor-client");
        assert_eq!(principal.realm(), "example");
        assert_eq!(principal.assurance(), AssuranceLevel::Aal2);
        assert!(principal.scopes().contains("example:inspect"));
        assert!(principal.roles().contains("member"));
        assert!(principal.authentication_methods().contains("passkey"));
    }

    #[tokio::test]
    async fn every_product_boundary_fails_closed_as_forbidden() {
        let verifier = verifier();
        let cases = [
            ("azp", json!("unknown-client")),
            ("project", json!("other-realm")),
            ("sid", Value::Null),
            ("scope", json!("mcp:read")),
            ("roles", json!(["guest"])),
            ("aal", json!(1)),
        ];
        for (field, replacement) in cases {
            let mut value = claims();
            value[field] = replacement;
            let failure = verifier
                .verify_bearer(&token(KEY_ID, &value))
                .await
                .expect_err("policy must deny");
            assert_eq!(failure, AuthorizationFailure::Forbidden, "field {field}");
        }
    }

    #[tokio::test]
    async fn contradictory_client_or_assurance_claims_fail_closed() {
        let verifier = verifier();
        let mut client = claims();
        client["client_id"] = json!("openai-client");
        assert_eq!(
            verifier.verify_bearer(&token(KEY_ID, &client)).await,
            Err(AuthorizationFailure::Forbidden)
        );

        let mut assurance = claims();
        assurance["acr"] = json!("urn:oresoftware:loa:3");
        assert_eq!(
            verifier.verify_bearer(&token(KEY_ID, &assurance)).await,
            Err(AuthorizationFailure::Forbidden)
        );
    }

    #[tokio::test]
    async fn issuer_audience_expiry_algorithm_and_key_id_are_authentication() {
        let verifier = verifier();
        for (field, replacement) in [
            ("iss", json!("https://evil.example.test")),
            ("aud", json!("https://mcp.other.test/mcp")),
            ("exp", json!(now_seconds().saturating_sub(600))),
        ] {
            let mut value = claims();
            value[field] = replacement;
            assert_eq!(
                verifier.verify_bearer(&token(KEY_ID, &value)).await,
                Err(AuthorizationFailure::InvalidCredential),
                "field {field}"
            );
        }
        let mut additional_audience = claims();
        additional_audience["aud"] =
            json!(["https://mcp.example.test/mcp", "https://mcp.other.test/mcp"]);
        assert_eq!(
            verifier
                .verify_bearer(&token(KEY_ID, &additional_audience))
                .await,
            Err(AuthorizationFailure::InvalidCredential)
        );
        let mut missing_issued_at = claims();
        missing_issued_at
            .as_object_mut()
            .expect("claims object")
            .remove("iat");
        assert_eq!(
            verifier
                .verify_bearer(&token(KEY_ID, &missing_issued_at))
                .await,
            Err(AuthorizationFailure::InvalidCredential)
        );
        assert_eq!(
            verifier
                .verify_bearer(&token("unknown-key", &claims()))
                .await,
            Err(AuthorizationFailure::InvalidCredential)
        );
        assert_eq!(
            verifier.verify_bearer("not.a.jwt").await,
            Err(AuthorizationFailure::InvalidCredential)
        );
    }

    #[test]
    fn static_jwks_rejects_wrong_algorithms_duplicates_and_oversize() {
        let mut wrong_algorithm: Value =
            serde_json::from_slice(&jwks(KEY_ID)).expect("fixture JWKS");
        wrong_algorithm["keys"][0]["alg"] = json!("ES384");
        assert!(SharedAuthVerifier::with_static_jwks_json(
            policy(),
            &serde_json::to_vec(&wrong_algorithm).expect("fixture")
        )
        .is_err());

        let key: Value = serde_json::from_slice::<Value>(&jwks(KEY_ID)).expect("fixture JWKS")
            ["keys"][0]
            .clone();
        let duplicate = serde_json::to_vec(&json!({"keys": [key.clone(), key]})).expect("fixture");
        assert!(SharedAuthVerifier::with_static_jwks_json(policy(), &duplicate).is_err());
        assert!(SharedAuthVerifier::with_static_jwks_json(
            policy(),
            &vec![b' '; MAX_JWKS_BYTES + 1]
        )
        .is_err());
    }

    #[test]
    fn access_tokens_and_failures_are_never_rendered() {
        let token = token(KEY_ID, &claims());
        assert!(!format!("{:?}", verifier().policy()).contains(&token));
        assert_eq!(
            AuthorizationFailure::InvalidCredential.to_string(),
            "invalid_credential"
        );
    }
}
