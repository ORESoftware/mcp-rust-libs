//! Shared Auth protected Streamable HTTP for the Rust MCP fleet.
//!
//! This crate turns one product-owned [`rmcp`] service into an OAuth protected
//! resource without turning the MCP endpoint into a credential relay. Shared
//! Auth access tokens are verified locally against a bounded JWKS cache, then
//! issuer, resource audience, authorized client, realm, session, scopes, roles,
//! and assurance are checked before the MCP transport sees a request.
//!
//! The verified [`RemotePrincipal`] is inserted into the HTTP request extensions
//! and is therefore available to product tools through `rmcp` request context.
//! The access token itself is never inserted or returned.

#![forbid(unsafe_code)]

mod policy;
mod router;
mod verifier;

pub use policy::{
    AssuranceLevel, RealmClaim, RemoteAuthPolicy, RemoteConfigError, RemoteMcpConfig,
    RemotePrincipal,
};
pub use router::protected_mcp_router;
pub use verifier::{AuthorizationFailure, SharedAuthVerifier, VerifierReadiness};

/// Returns the verified remote caller attached to an `rmcp` request context.
///
/// Streamable HTTP stores the HTTP request parts in the MCP extensions. Stdio
/// requests have no remote principal and return `None`, allowing one product
/// service implementation to support both transports without inventing an
/// identity for local clients.
#[must_use]
pub fn remote_principal(
    context: &rmcp::service::RequestContext<rmcp::RoleServer>,
) -> Option<&RemotePrincipal> {
    context
        .extensions
        .get::<axum::http::request::Parts>()?
        .extensions
        .get::<RemotePrincipal>()
}
