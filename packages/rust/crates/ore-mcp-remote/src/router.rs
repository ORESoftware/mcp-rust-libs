use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant},
};

use axum::{
    body::{to_bytes, Body},
    extract::State,
    http::{
        header::{AUTHORIZATION, CACHE_CONTROL, CONTENT_TYPE, RETRY_AFTER, WWW_AUTHENTICATE},
        uri::Authority,
        HeaderMap, HeaderValue, Method, Request, StatusCode,
    },
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::get,
    Json, Router,
};
use ore_mcp_runtime::ExactProtocol;
use rmcp::{
    model::ProtocolVersion,
    transport::streamable_http_server::{
        session::{local::LocalSessionManager, SessionManager},
        StreamableHttpServerConfig, StreamableHttpService,
    },
    RoleServer, Service,
};
use serde::Serialize;
use tokio::sync::{OwnedSemaphorePermit, RwLock, Semaphore};
use url::Url;

use crate::{
    verifier::AuthorizationFailure, RemoteMcpConfig, RemotePrincipal, SharedAuthVerifier,
    VerifierReadiness,
};

const MCP_SESSION_ID: &str = "mcp-session-id";
const MAX_SESSION_ID_BYTES: usize = 256;
const SESSION_BINDING_IDLE: Duration = Duration::from_secs(10 * 60);

#[derive(Clone)]
struct AuthState {
    config: Arc<RemoteMcpConfig>,
    verifier: SharedAuthVerifier,
    sessions: Arc<RwLock<HashMap<String, SessionBinding>>>,
    session_manager: Arc<LocalSessionManager>,
    session_permits: Arc<Semaphore>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct PrincipalBinding {
    subject: String,
    shared_auth_session: String,
    oauth_client: String,
    realm: String,
}

impl From<&RemotePrincipal> for PrincipalBinding {
    fn from(principal: &RemotePrincipal) -> Self {
        Self {
            subject: principal.subject().to_owned(),
            shared_auth_session: principal.session_id().to_owned(),
            oauth_client: principal.authorized_client().to_owned(),
            realm: principal.realm().to_owned(),
        }
    }
}

struct SessionBinding {
    principal: PrincipalBinding,
    last_seen: Instant,
    _permit: OwnedSemaphorePermit,
}

#[derive(Serialize)]
struct ProtectedResourceMetadata {
    resource: String,
    authorization_servers: [String; 1],
    bearer_methods_supported: [&'static str; 1],
    scopes_supported: Vec<String>,
    resource_name: String,
}

#[derive(Serialize)]
struct Health<'a> {
    state: &'a str,
}

#[derive(Serialize)]
struct ErrorBody<'a> {
    error: &'a str,
}

/// Builds public discovery/health routes and one protected `/mcp` service.
///
/// The same `rmcp` service is usable by every MCP client. The router publishes
/// RFC 9728 metadata at both the root compatibility location and the path-aware
/// location for the `/mcp` resource. The MCP subtree enforces the request-body
/// ceiling before `rmcp` buffers JSON and validates Shared Auth before invoking
/// product code.
///
/// Stateful mode additionally binds every `Mcp-Session-Id` to the verified
/// Shared Auth subject, Shared Auth session, OAuth client, and realm. The
/// in-memory table is intentionally bounded. Multi-replica deployments should
/// use sticky routing to one pod or stateless mode until a paired distributed
/// MCP-session and identity-binding store is configured.
///
/// Product handlers remain responsible for bounding serialized tool results at
/// [`RemoteMcpConfig::response_body_max_bytes`] and for authorizing individual
/// resources/mutations against the [`RemotePrincipal`] request extension.
pub fn protected_mcp_router<S, F>(
    config: RemoteMcpConfig,
    verifier: SharedAuthVerifier,
    service_factory: F,
) -> Router
where
    S: Service<RoleServer> + Send + 'static,
    F: Fn() -> Result<S, std::io::Error> + Clone + Send + Sync + 'static,
{
    let session_manager = Arc::new(LocalSessionManager::default());
    let state = AuthState {
        session_permits: Arc::new(Semaphore::new(config.max_sessions())),
        config: Arc::new(config),
        verifier,
        sessions: Arc::new(RwLock::new(HashMap::new())),
        session_manager: session_manager.clone(),
    };
    let exact_factory = move || {
        service_factory().map(|service| ExactProtocol::new(service, ProtocolVersion::V_2025_11_25))
    };
    let transport_config = StreamableHttpServerConfig::default()
        .with_allowed_hosts(state.config.allowed_hosts().iter().cloned())
        .with_allowed_origins(state.config.allowed_origins().iter().cloned())
        .with_stateful_mode(state.config.stateful())
        .with_json_response(!state.config.stateful());
    let service: StreamableHttpService<ExactProtocol<S>, LocalSessionManager> =
        StreamableHttpService::new(exact_factory, session_manager, transport_config);

    let protected = Router::new()
        .route_service("/mcp", service)
        .layer(middleware::from_fn_with_state(
            state.clone(),
            bound_mcp_body,
        ))
        .layer(middleware::from_fn_with_state(state.clone(), authorize_mcp))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            validate_inbound_authority,
        ));
    let public = Router::new()
        .route(
            "/.well-known/oauth-protected-resource",
            get(protected_resource_metadata),
        )
        .route(
            "/.well-known/oauth-protected-resource/mcp",
            get(protected_resource_metadata),
        )
        .route("/health/live", get(liveness))
        .route("/health/ready", get(readiness))
        .with_state(state);
    public.merge(protected)
}

async fn validate_inbound_authority(
    State(state): State<AuthState>,
    request: Request<Body>,
    next: Next,
) -> Response {
    let host = match single_header(request.headers(), axum::http::header::HOST) {
        Ok(Some(value)) => normalized_authority(value),
        Ok(None) => request
            .uri()
            .authority()
            .and_then(|value| normalized_authority(value.as_str())),
        Err(()) => None,
    };
    let Some(host) = host else {
        return inbound_policy_response(StatusCode::BAD_REQUEST, "invalid_authority");
    };
    if !state
        .config
        .allowed_hosts()
        .iter()
        .filter_map(|allowed| normalized_authority(allowed))
        .any(|allowed| allowed == host)
    {
        return inbound_policy_response(StatusCode::FORBIDDEN, "forbidden_authority");
    }

    let origin = match single_header(request.headers(), axum::http::header::ORIGIN) {
        Ok(Some(value)) => match normalized_origin(value) {
            Some(origin) => Some(origin),
            None => return inbound_policy_response(StatusCode::BAD_REQUEST, "invalid_origin"),
        },
        Ok(None) => None,
        Err(()) => return inbound_policy_response(StatusCode::BAD_REQUEST, "invalid_origin"),
    };
    if origin.is_some_and(|origin| {
        !state
            .config
            .allowed_origins()
            .iter()
            .filter_map(|allowed| normalized_origin(allowed))
            .any(|allowed| allowed == origin)
    }) {
        return inbound_policy_response(StatusCode::FORBIDDEN, "forbidden_origin");
    }
    next.run(request).await
}

fn single_header(
    headers: &HeaderMap,
    name: axum::http::header::HeaderName,
) -> Result<Option<&str>, ()> {
    let mut values = headers.get_all(name).iter();
    let Some(value) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() {
        return Err(());
    }
    value.to_str().map(Some).map_err(|_| ())
}

fn normalized_authority(value: &str) -> Option<(String, u16)> {
    if value.is_empty() || value.len() > 320 || value.chars().any(char::is_whitespace) {
        return None;
    }
    let authority = Authority::try_from(value).ok()?;
    let host = authority.host().trim_end_matches('.').to_ascii_lowercase();
    (!host.is_empty()).then(|| (host, authority.port_u16().unwrap_or(443)))
}

fn normalized_origin(value: &str) -> Option<(String, String, u16)> {
    if value.is_empty() || value.len() > 2048 || value.chars().any(char::is_whitespace) {
        return None;
    }
    let origin = Url::parse(value).ok()?;
    if origin.scheme() != "https"
        || origin.host().is_none()
        || !origin.username().is_empty()
        || origin.password().is_some()
        || origin.path() != "/"
        || origin.query().is_some()
        || origin.fragment().is_some()
    {
        return None;
    }
    Some((
        origin.scheme().to_owned(),
        origin
            .host_str()?
            .trim_end_matches('.')
            .to_ascii_lowercase(),
        origin.port_or_known_default()?,
    ))
}

fn inbound_policy_response(status: StatusCode, error: &'static str) -> Response {
    let mut response = (status, Json(ErrorBody { error })).into_response();
    response
        .headers_mut()
        .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

async fn bound_mcp_body(
    State(state): State<AuthState>,
    request: Request<Body>,
    next: Next,
) -> Response {
    let (parts, body) = request.into_parts();
    match to_bytes(body, state.config.request_body_max_bytes()).await {
        Ok(bytes) => {
            next.run(Request::from_parts(parts, Body::from(bytes)))
                .await
        }
        Err(_) => {
            let mut response = (
                StatusCode::PAYLOAD_TOO_LARGE,
                Json(ErrorBody {
                    error: "payload_too_large",
                }),
            )
                .into_response();
            response
                .headers_mut()
                .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
            response
        }
    }
}

async fn protected_resource_metadata(
    State(state): State<AuthState>,
) -> Json<ProtectedResourceMetadata> {
    let policy = state.config.auth();
    let scopes = policy.required_scopes().iter().cloned().collect();
    Json(ProtectedResourceMetadata {
        resource: policy.resource().to_owned(),
        authorization_servers: [policy.issuer().to_owned()],
        bearer_methods_supported: ["header"],
        scopes_supported: scopes,
        resource_name: format!("{} MCP server", policy.realm()),
    })
}

async fn liveness() -> StatusCode {
    StatusCode::NO_CONTENT
}

async fn readiness(State(state): State<AuthState>) -> Response {
    match state.verifier.readiness().await {
        VerifierReadiness::Ready => (
            StatusCode::OK,
            Json(Health {
                state: VerifierReadiness::Ready.as_str(),
            }),
        )
            .into_response(),
        VerifierReadiness::Grace => (
            StatusCode::OK,
            Json(Health {
                state: VerifierReadiness::Grace.as_str(),
            }),
        )
            .into_response(),
        VerifierReadiness::Unavailable => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(Health {
                state: VerifierReadiness::Unavailable.as_str(),
            }),
        )
            .into_response(),
    }
}

async fn authorize_mcp(
    State(state): State<AuthState>,
    mut request: Request<Body>,
    next: Next,
) -> Response {
    let token = match bearer_token(request.headers()) {
        Ok(token) => token,
        Err(failure) => return authorization_response(&state, failure),
    };
    let principal = match state.verifier.verify_bearer(token).await {
        Ok(principal) => principal,
        Err(failure) => return authorization_response(&state, failure),
    };
    let binding = PrincipalBinding::from(&principal);
    let incoming_session = match session_id(request.headers()) {
        Ok(value) => value,
        Err(failure) => return authorization_response(&state, failure),
    };
    let new_session_permit = if state.config.stateful() {
        if let Some(session_id) = incoming_session.as_deref() {
            let mut sessions = state.sessions.write().await;
            let Some(session) = sessions.get_mut(session_id) else {
                return authorization_response(&state, AuthorizationFailure::Forbidden);
            };
            if session.principal != binding {
                return authorization_response(&state, AuthorizationFailure::Forbidden);
            }
            session.last_seen = Instant::now();
            None
        } else {
            state
                .sessions
                .write()
                .await
                .retain(|_, session| session.last_seen.elapsed() <= SESSION_BINDING_IDLE);
            match state.session_permits.clone().try_acquire_owned() {
                Ok(permit) => Some(permit),
                Err(_) => {
                    return authorization_response(&state, AuthorizationFailure::SessionCapacity);
                }
            }
        }
    } else if incoming_session.is_some() {
        return authorization_response(&state, AuthorizationFailure::Forbidden);
    } else {
        None
    };

    let method = request.method().clone();
    request.headers_mut().remove(AUTHORIZATION);
    request.extensions_mut().insert(principal);
    let mut response = next.run(request).await;

    if state.config.stateful() {
        let response_session = match session_id(response.headers()) {
            Ok(value) => value,
            Err(_) => {
                return authorization_response(&state, AuthorizationFailure::AuthorityUnavailable);
            }
        };
        if let Some(permit) = new_session_permit {
            if response.status().is_success() {
                let Some(created_session) = response_session else {
                    return authorization_response(
                        &state,
                        AuthorizationFailure::AuthorityUnavailable,
                    );
                };
                let mut sessions = state.sessions.write().await;
                if sessions.contains_key(&created_session) {
                    return authorization_response(
                        &state,
                        AuthorizationFailure::AuthorityUnavailable,
                    );
                }
                sessions.insert(
                    created_session,
                    SessionBinding {
                        principal: binding,
                        last_seen: Instant::now(),
                        _permit: permit,
                    },
                );
            } else if let Some(created_session) = response_session {
                let created_session: Arc<str> = Arc::from(created_session);
                let _ = state.session_manager.close_session(&created_session).await;
            }
        } else if let (Some(incoming_session), Some(response_session)) =
            (incoming_session.as_deref(), response_session.as_deref())
        {
            if incoming_session != response_session {
                return authorization_response(&state, AuthorizationFailure::AuthorityUnavailable);
            }
        }
        if let Some(session_id) = incoming_session.as_deref() {
            if (method == Method::DELETE && response.status().is_success())
                || response.status() == StatusCode::NOT_FOUND
            {
                state.sessions.write().await.remove(session_id);
            }
        }
    }
    response
        .headers_mut()
        .insert(CACHE_CONTROL, HeaderValue::from_static("no-store, private"));
    response
}

fn bearer_token(headers: &HeaderMap) -> Result<&str, AuthorizationFailure> {
    let mut values = headers.get_all(AUTHORIZATION).iter();
    let Some(value) = values.next() else {
        return Err(AuthorizationFailure::MissingCredential);
    };
    if values.next().is_some() {
        return Err(AuthorizationFailure::InvalidCredential);
    }
    let value = value
        .to_str()
        .map_err(|_| AuthorizationFailure::InvalidCredential)?;
    let (scheme, token) = value
        .split_once(' ')
        .ok_or(AuthorizationFailure::InvalidCredential)?;
    if !scheme.eq_ignore_ascii_case("Bearer")
        || token.is_empty()
        || token.starts_with(' ')
        || token.bytes().any(|byte| byte.is_ascii_whitespace())
    {
        return Err(AuthorizationFailure::InvalidCredential);
    }
    Ok(token)
}

fn session_id(headers: &HeaderMap) -> Result<Option<String>, AuthorizationFailure> {
    let mut values = headers.get_all(MCP_SESSION_ID).iter();
    let Some(value) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() {
        return Err(AuthorizationFailure::Forbidden);
    }
    let value = value
        .to_str()
        .map_err(|_| AuthorizationFailure::Forbidden)?;
    valid_session_id(value)
        .then(|| value.to_owned())
        .map(Some)
        .ok_or(AuthorizationFailure::Forbidden)
}

fn valid_session_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_SESSION_ID_BYTES
        && value.bytes().all(|byte| matches!(byte, 0x21..=0x7e))
        && !value.contains(',')
}

fn authorization_response(state: &AuthState, failure: AuthorizationFailure) -> Response {
    let (status, error, challenge_error) = match failure {
        AuthorizationFailure::MissingCredential => (StatusCode::UNAUTHORIZED, "unauthorized", None),
        AuthorizationFailure::InvalidCredential => (
            StatusCode::UNAUTHORIZED,
            "unauthorized",
            Some("invalid_token"),
        ),
        AuthorizationFailure::Forbidden => (
            StatusCode::FORBIDDEN,
            "forbidden",
            Some("insufficient_scope"),
        ),
        AuthorizationFailure::AuthorityUnavailable | AuthorizationFailure::SessionCapacity => (
            StatusCode::SERVICE_UNAVAILABLE,
            "temporarily_unavailable",
            None,
        ),
    };
    let mut response = (status, Json(ErrorBody { error })).into_response();
    response
        .headers_mut()
        .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
        .headers_mut()
        .insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    if status == StatusCode::SERVICE_UNAVAILABLE {
        response
            .headers_mut()
            .insert(RETRY_AFTER, HeaderValue::from_static("5"));
    } else if let Ok(challenge) = bearer_challenge(state, challenge_error) {
        response.headers_mut().insert(WWW_AUTHENTICATE, challenge);
    }
    response
}

fn bearer_challenge(
    state: &AuthState,
    error: Option<&str>,
) -> Result<HeaderValue, AuthorizationFailure> {
    let scope = state
        .config
        .auth()
        .required_scopes()
        .iter()
        .cloned()
        .collect::<Vec<_>>()
        .join(" ");
    let mut challenge = format!(
        "Bearer resource_metadata=\"{}\", scope=\"{}\"",
        state.config.auth().resource_metadata_url(),
        scope
    );
    if let Some(error) = error {
        challenge.push_str(&format!(", error=\"{error}\""));
    }
    HeaderValue::from_str(&challenge).map_err(|_| AuthorizationFailure::AuthorityUnavailable)
}

#[cfg(test)]
mod tests {
    use std::future::Future;

    use axum::{body::to_bytes, http::Request};
    use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
    use p256::{
        pkcs8::{EncodePrivateKey, LineEnding},
        SecretKey,
    };
    use rmcp::{
        model::{InitializeRequestParams, InitializeResult, ServerInfo},
        service::RequestContext,
        ErrorData, RoleServer, ServerHandler,
    };
    use serde_json::{json, Value};
    use tower::ServiceExt;

    use super::*;
    use crate::{AssuranceLevel, RealmClaim, RemoteAuthPolicy};

    const KEY_ID: &str = "router-test-key";
    const INITIALIZE: &str = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"test","version":"1.0"}}}"#;

    #[derive(Clone, Default)]
    struct TestServer;

    impl ServerHandler for TestServer {
        fn get_info(&self) -> ServerInfo {
            ServerInfo::default()
        }

        fn initialize(
            &self,
            request: InitializeRequestParams,
            context: RequestContext<RoleServer>,
        ) -> impl Future<Output = Result<InitializeResult, ErrorData>> + Send + '_ {
            let principal = crate::remote_principal(&context).expect("verified principal");
            assert_eq!(principal.subject(), "user-1");
            let parts = context
                .extensions
                .get::<axum::http::request::Parts>()
                .expect("HTTP request parts");
            assert!(parts.headers.get(AUTHORIZATION).is_none());
            context.peer.set_peer_info(request.clone());
            let mut info = ServerHandler::get_info(self);
            info.protocol_version = request.protocol_version;
            std::future::ready(Ok(info))
        }
    }

    fn secret_key() -> SecretKey {
        SecretKey::from_slice(&[7_u8; 32]).expect("valid deterministic key")
    }

    fn jwks() -> Vec<u8> {
        let mut jwk =
            serde_json::to_value(secret_key().public_key().to_jwk()).expect("JWK serializes");
        let object = jwk.as_object_mut().expect("JWK object");
        object.insert("kid".into(), KEY_ID.into());
        object.insert("alg".into(), "ES256".into());
        object.insert("use".into(), "sig".into());
        serde_json::to_vec(&json!({"keys": [jwk]})).expect("JWKS serializes")
    }

    fn token_for(subject: &str, shared_session: &str) -> String {
        let now = super::super::verifier::now_seconds();
        let claims = json!({
            "iss": "https://auth.example.test",
            "aud": "https://mcp.example.test/mcp",
            "sub": subject,
            "iat": now,
            "nbf": now.saturating_sub(1),
            "exp": now + 600,
            "sid": shared_session,
            "azp": "openai-client",
            "project": "example",
            "scope": "mcp:read example:inspect",
            "roles": ["member"],
            "amr": ["totp"],
            "aal": 2,
            "acr": "urn:oresoftware:loa:2"
        });
        let private = secret_key()
            .to_pkcs8_pem(LineEnding::LF)
            .expect("private key encodes");
        let mut header = Header::new(Algorithm::ES256);
        header.kid = Some(KEY_ID.into());
        encode(
            &header,
            &claims,
            &EncodingKey::from_ec_pem(private.as_bytes()).expect("encoding key"),
        )
        .expect("token")
    }

    fn token() -> String {
        token_for("user-1", "shared-session-1")
    }

    fn configured_router(stateful: bool, max_sessions: usize) -> Router {
        let policy = RemoteAuthPolicy::new(
            "https://mcp.example.test/mcp",
            "https://auth.example.test",
            "https://auth.example.test/.well-known/jwks.json",
            ["openai-client"],
            RealmClaim::Project,
            "example",
            AssuranceLevel::Aal2,
            ["mcp:read", "example:inspect"],
            ["member"],
        )
        .expect("policy");
        let verifier =
            SharedAuthVerifier::with_static_jwks_json(policy.clone(), &jwks()).expect("verifier");
        let config =
            RemoteMcpConfig::new(policy, ["mcp.example.test"], ["https://app.example.test"])
                .expect("config")
                .with_stateful_mode(stateful)
                .with_max_sessions(max_sessions)
                .expect("session bound")
                .with_body_limits(2048, 4096)
                .expect("bounds");
        protected_mcp_router(config, verifier, || Ok(TestServer))
    }

    fn router() -> Router {
        configured_router(false, 10)
    }

    #[tokio::test]
    async fn metadata_and_health_are_public_but_mcp_challenges() {
        let metadata = router()
            .oneshot(
                Request::get("/.well-known/oauth-protected-resource/mcp")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(metadata.status(), StatusCode::OK);
        let body = to_bytes(metadata.into_body(), 4096)
            .await
            .expect("bounded body");
        let document: Value = serde_json::from_slice(&body).expect("metadata JSON");
        assert_eq!(document["resource"], "https://mcp.example.test/mcp");
        assert_eq!(
            document["authorization_servers"][0],
            "https://auth.example.test"
        );

        let unauthorized = router()
            .oneshot(
                Request::post("/mcp")
                    .header("host", "mcp.example.test")
                    .body(Body::from(INITIALIZE))
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(unauthorized.status(), StatusCode::UNAUTHORIZED);
        let challenge = unauthorized
            .headers()
            .get(WWW_AUTHENTICATE)
            .and_then(|value| value.to_str().ok())
            .expect("challenge");
        assert!(challenge.contains("resource_metadata=\"https://mcp.example.test/"));
        assert!(!challenge.contains("error_description"));
    }

    #[tokio::test]
    async fn authority_and_origin_are_exactly_validated_before_authentication() {
        let missing_host = router()
            .oneshot(
                Request::post("/mcp")
                    .header(AUTHORIZATION, "Bearer invalid")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(missing_host.status(), StatusCode::BAD_REQUEST);

        let forbidden_host = router()
            .oneshot(
                Request::post("/mcp")
                    .header("host", "mcp.example.test.attacker.test")
                    .header(AUTHORIZATION, "Bearer invalid")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(forbidden_host.status(), StatusCode::FORBIDDEN);

        let forbidden_origin = router()
            .oneshot(
                Request::post("/mcp")
                    .header("host", "mcp.example.test")
                    .header("origin", "https://app.example.test.attacker.test")
                    .header(AUTHORIZATION, "Bearer invalid")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(forbidden_origin.status(), StatusCode::FORBIDDEN);

        let normalized_default_port = router()
            .oneshot(
                Request::post("/mcp")
                    .header("host", "mcp.example.test:443")
                    .header("origin", "https://app.example.test:443")
                    .header(AUTHORIZATION, "Bearer invalid")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(normalized_default_port.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn authenticated_final_protocol_reaches_the_same_rmcp_service() {
        let response = router()
            .oneshot(
                Request::post("/mcp")
                    .header("host", "mcp.example.test")
                    .header(AUTHORIZATION, format!("Bearer {}", token()))
                    .header(CONTENT_TYPE, "application/json")
                    .header("accept", "application/json, text/event-stream")
                    .body(Body::from(INITIALIZE))
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response
                .headers()
                .get(CACHE_CONTROL)
                .and_then(|value| value.to_str().ok()),
            Some("no-store, private")
        );
        let body = to_bytes(response.into_body(), 4096)
            .await
            .expect("bounded body");
        let document: Value = serde_json::from_slice(&body).expect("JSON-RPC response");
        assert_eq!(document["jsonrpc"], "2.0");
        assert_eq!(document["result"]["protocolVersion"], "2025-11-25");
    }

    #[tokio::test]
    async fn stateful_sessions_are_identity_bound_capacity_reserved_and_released() {
        let server = configured_router(true, 1);
        let first = server
            .clone()
            .oneshot(
                Request::post("/mcp")
                    .header("host", "mcp.example.test")
                    .header(AUTHORIZATION, format!("Bearer {}", token()))
                    .header(CONTENT_TYPE, "application/json")
                    .header("accept", "application/json, text/event-stream")
                    .body(Body::from(INITIALIZE))
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(first.status(), StatusCode::OK);
        let session = first
            .headers()
            .get(MCP_SESSION_ID)
            .and_then(|value| value.to_str().ok())
            .expect("created session")
            .to_owned();
        drop(first);

        let wrong_identity = server
            .clone()
            .oneshot(
                Request::delete("/mcp")
                    .header("host", "mcp.example.test")
                    .header(
                        AUTHORIZATION,
                        format!("Bearer {}", token_for("user-2", "shared-session-2")),
                    )
                    .header(MCP_SESSION_ID, &session)
                    .header("mcp-protocol-version", "2025-11-25")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(wrong_identity.status(), StatusCode::FORBIDDEN);

        let capacity = server
            .clone()
            .oneshot(
                Request::post("/mcp")
                    .header("host", "mcp.example.test")
                    .header(AUTHORIZATION, format!("Bearer {}", token()))
                    .header(CONTENT_TYPE, "application/json")
                    .header("accept", "application/json, text/event-stream")
                    .body(Body::from(INITIALIZE))
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(capacity.status(), StatusCode::SERVICE_UNAVAILABLE);

        let deleted = server
            .clone()
            .oneshot(
                Request::delete("/mcp")
                    .header("host", "mcp.example.test")
                    .header(AUTHORIZATION, format!("Bearer {}", token()))
                    .header(MCP_SESSION_ID, &session)
                    .header("mcp-protocol-version", "2025-11-25")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(deleted.status(), StatusCode::ACCEPTED);

        let replacement = server
            .oneshot(
                Request::post("/mcp")
                    .header("host", "mcp.example.test")
                    .header(AUTHORIZATION, format!("Bearer {}", token()))
                    .header(CONTENT_TYPE, "application/json")
                    .header("accept", "application/json, text/event-stream")
                    .body(Body::from(INITIALIZE))
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(replacement.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn malformed_duplicate_and_stateless_session_headers_fail_closed() {
        let malformed = router()
            .oneshot(
                Request::post("/mcp")
                    .header("host", "mcp.example.test")
                    .header(AUTHORIZATION, "Basic not-bearer")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(malformed.status(), StatusCode::UNAUTHORIZED);

        let mut duplicate = Request::post("/mcp")
            .header("host", "mcp.example.test")
            .body(Body::empty())
            .expect("request");
        duplicate.headers_mut().append(
            AUTHORIZATION,
            HeaderValue::from_static("Bearer first.invalid.token"),
        );
        duplicate.headers_mut().append(
            AUTHORIZATION,
            HeaderValue::from_static("Bearer second.invalid.token"),
        );
        let duplicate = router().oneshot(duplicate).await.expect("response");
        assert_eq!(duplicate.status(), StatusCode::UNAUTHORIZED);

        let session = router()
            .oneshot(
                Request::post("/mcp")
                    .header("host", "mcp.example.test")
                    .header(AUTHORIZATION, format!("Bearer {}", token()))
                    .header(MCP_SESSION_ID, "not-allowed-in-stateless-mode")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(session.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn request_body_limit_runs_before_rmcp_buffers_json() {
        let response = router()
            .oneshot(
                Request::post("/mcp")
                    .header("host", "mcp.example.test")
                    .header(AUTHORIZATION, format!("Bearer {}", token()))
                    .header(CONTENT_TYPE, "application/json")
                    .header("accept", "application/json, text/event-stream")
                    .body(Body::from(vec![b'x'; 2049]))
                    .expect("request"),
            )
            .await
            .expect("response");
        assert!(
            matches!(
                response.status(),
                StatusCode::PAYLOAD_TOO_LARGE | StatusCode::BAD_REQUEST
            ),
            "unexpected status {}",
            response.status()
        );
    }
}
