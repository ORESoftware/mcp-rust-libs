//! Hardened policy primitives for diagnostic HTTP clients.

#![forbid(unsafe_code)]

use ore_mcp_safety::Bounds;
use url::{Host, Url};

/// HTTP policy shared by read-only diagnostic clients.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HttpPolicy {
    /// Request timeout in milliseconds.
    pub timeout_ms: u64,
    /// Maximum response body accepted before aborting.
    pub max_body_bytes: usize,
    /// Whether plain HTTP is accepted for exact loopback development endpoints.
    pub allow_loopback_http: bool,
    /// Redirects are deliberately disabled by default.
    pub follow_redirects: bool,
}

impl HttpPolicy {
    /// Constructs the fleet default policy.
    #[must_use]
    pub const fn diagnostic_default() -> Self {
        Self {
            timeout_ms: 10_000,
            max_body_bytes: Bounds::DEFAULT.max_json_bytes,
            allow_loopback_http: true,
            follow_redirects: false,
        }
    }

    /// Parses and validates a complete endpoint.
    ///
    /// HTTPS is accepted for tokenless diagnostics. Plain HTTP is accepted only
    /// for exact loopback IP addresses or the exact `localhost` hostname.
    ///
    /// # Errors
    ///
    /// Returns a specific [`HttpPolicyError`] for unsafe endpoints.
    pub fn parse_endpoint(self, endpoint: &str) -> Result<Url, HttpPolicyError> {
        if endpoint.is_empty()
            || endpoint.len() > 4096
            || endpoint
                .chars()
                .any(|character| character.is_control() || character.is_whitespace())
        {
            return Err(HttpPolicyError::MalformedEndpoint);
        }
        let parsed = Url::parse(endpoint).map_err(|_| HttpPolicyError::MalformedEndpoint)?;
        if parsed.host().is_none() {
            return Err(HttpPolicyError::MalformedEndpoint);
        }
        if !parsed.username().is_empty() || parsed.password().is_some() {
            return Err(HttpPolicyError::CredentialsInUrl);
        }
        if parsed.fragment().is_some() {
            return Err(HttpPolicyError::FragmentForbidden);
        }
        match parsed.scheme() {
            "https" => Ok(parsed),
            "http" if self.allow_loopback_http && is_loopback(&parsed) => Ok(parsed),
            "http" => Err(HttpPolicyError::InsecureEndpoint),
            _ => Err(HttpPolicyError::UnsupportedScheme),
        }
    }

    /// Validates a base URL, which must not contain a query or fragment.
    ///
    /// # Errors
    ///
    /// Returns [`HttpPolicyError::QueryForbidden`] for query-bearing base URLs
    /// and otherwise delegates to [`Self::parse_endpoint`].
    pub fn parse_base_url(self, endpoint: &str) -> Result<Url, HttpPolicyError> {
        let parsed = self.parse_endpoint(endpoint)?;
        if parsed.query().is_some() {
            return Err(HttpPolicyError::QueryForbidden);
        }
        Ok(parsed)
    }

    /// Validates a bearer-authenticated endpoint against an exact host allowlist.
    ///
    /// Redirects must remain disabled by the concrete HTTP client. The allowlist
    /// comparison is case-insensitive and ignores one terminal DNS dot; suffix
    /// matching is never used.
    ///
    /// # Errors
    ///
    /// Returns [`HttpPolicyError::HostNotAllowed`] when the endpoint host is not
    /// explicitly listed.
    pub fn parse_bearer_endpoint(
        self,
        endpoint: &str,
        allowed_hosts: &[&str],
    ) -> Result<Url, HttpPolicyError> {
        let parsed = self.parse_endpoint(endpoint)?;
        let actual = normalized_host(&parsed).ok_or(HttpPolicyError::MalformedEndpoint)?;
        let allowed = allowed_hosts.iter().any(|candidate| {
            let candidate = candidate.trim().trim_end_matches('.');
            !candidate.is_empty() && candidate.eq_ignore_ascii_case(&actual)
        });
        if !allowed {
            return Err(HttpPolicyError::HostNotAllowed);
        }
        Ok(parsed)
    }

    /// Retained boolean-shaped endpoint validation for simple callers.
    ///
    /// # Errors
    ///
    /// Delegates to [`Self::parse_endpoint`].
    pub fn validate_endpoint(self, endpoint: &str) -> Result<(), HttpPolicyError> {
        self.parse_endpoint(endpoint).map(|_| ())
    }

    /// Rejects an already-buffered response body above the configured maximum.
    /// Streaming clients should enforce this same limit before buffering.
    ///
    /// # Errors
    ///
    /// Returns [`HttpPolicyError::BodyTooLarge`] when `body` exceeds the
    /// configured maximum.
    pub fn check_body(self, body: &[u8]) -> Result<(), HttpPolicyError> {
        if body.len() > self.max_body_bytes {
            Err(HttpPolicyError::BodyTooLarge)
        } else {
            Ok(())
        }
    }
}

impl Default for HttpPolicy {
    fn default() -> Self {
        Self::diagnostic_default()
    }
}

fn is_loopback(url: &Url) -> bool {
    match url.host() {
        Some(Host::Domain(domain)) => domain
            .trim_end_matches('.')
            .eq_ignore_ascii_case("localhost"),
        Some(Host::Ipv4(address)) => address.is_loopback(),
        Some(Host::Ipv6(address)) => address.is_loopback(),
        None => false,
    }
}

fn normalized_host(url: &Url) -> Option<String> {
    url.host_str()
        .map(|host| host.trim_end_matches('.').to_ascii_lowercase())
}

/// Fail-closed HTTP policy errors suitable for sanitized mapping.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HttpPolicyError {
    /// URL parsing failed.
    MalformedEndpoint,
    /// Only HTTPS and constrained loopback HTTP are supported.
    UnsupportedScheme,
    /// Plain HTTP was used for a non-loopback endpoint.
    InsecureEndpoint,
    /// URL user-info could leak credentials.
    CredentialsInUrl,
    /// Fragments are not sent to servers and are forbidden for clarity.
    FragmentForbidden,
    /// Base URLs must not contain a query.
    QueryForbidden,
    /// A bearer-authenticated endpoint was not on the exact host allowlist.
    HostNotAllowed,
    /// The response exceeds the configured bound.
    BodyTooLarge,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoint_policy_accepts_https_and_exact_loopback_only() {
        let policy = HttpPolicy::default();
        assert!(policy
            .validate_endpoint("https://api.example.test/v1")
            .is_ok());
        assert!(policy
            .validate_endpoint("http://127.0.0.1:8080/health")
            .is_ok());
        assert!(policy.validate_endpoint("http://[::1]:8080/health").is_ok());
        assert!(policy
            .validate_endpoint("http://LOCALHOST.:8080/health")
            .is_ok());
        for endpoint in [
            "http://example.test/v1",
            "http://127.0.0.1.example.test/v1",
            "http://localhost.example.test/v1",
        ] {
            assert_eq!(
                policy.validate_endpoint(endpoint),
                Err(HttpPolicyError::InsecureEndpoint)
            );
        }
    }

    #[test]
    fn credentials_queries_and_fragments_fail_closed_for_base_urls() {
        let policy = HttpPolicy::default();
        assert_eq!(
            policy.validate_endpoint("https://user:secret@example.test"),
            Err(HttpPolicyError::CredentialsInUrl)
        );
        assert_eq!(
            policy.parse_base_url("https://example.test/api?tenant=one"),
            Err(HttpPolicyError::QueryForbidden)
        );
        assert_eq!(
            policy.validate_endpoint("https://example.test/api#fragment"),
            Err(HttpPolicyError::FragmentForbidden)
        );
        assert!(!policy.follow_redirects);
    }

    #[test]
    fn bearer_hosts_use_exact_matching_never_suffix_matching() {
        let policy = HttpPolicy::default();
        assert!(policy
            .parse_bearer_endpoint("https://api.github.com/repos", &["api.github.com"])
            .is_ok());
        assert!(policy
            .parse_bearer_endpoint("https://API.GITHUB.COM./repos", &["api.github.com"])
            .is_ok());
        assert_eq!(
            policy.parse_bearer_endpoint(
                "https://api.github.com.attacker.test/repos",
                &["api.github.com"],
            ),
            Err(HttpPolicyError::HostNotAllowed)
        );
    }
}
