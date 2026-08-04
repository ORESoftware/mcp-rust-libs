//! Version-neutral bootstrap policy for Rust MCP servers.
//!
//! The crate deliberately does not depend on a particular `rmcp`,
//! OpenTelemetry, or HTTP-client release. Product servers keep their protocol
//! and exporter implementations while sharing the security-sensitive startup
//! policy that had drifted across the fleet.

#![forbid(unsafe_code)]

/// Strict command-line configuration discovery and redaction helpers.
pub mod config {
    use std::{
        error::Error,
        fmt,
        io,
        path::{Path, PathBuf},
    };

    /// Static locations used to find one server's `.cli-flags.toml` file.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub struct ConfigPathSpec {
        /// Environment variable that may override the configuration path.
        pub override_env: &'static str,
        /// File name searched from the working directory and executable path.
        pub file_name: &'static str,
        /// Installation subdirectory below `../share` beside the executable.
        pub install_share_subdir: &'static str,
    }

    impl ConfigPathSpec {
        /// Constructs the conventional MCP flag-file search policy.
        #[must_use]
        pub const fn cli_flags(
            override_env: &'static str,
            install_share_subdir: &'static str,
        ) -> Self {
            Self {
                override_env,
                file_name: ".cli-flags.toml",
                install_share_subdir,
            }
        }
    }

    /// Fail-closed startup-configuration errors that do not echo secret values.
    #[derive(Clone, Debug, Eq, PartialEq)]
    pub enum ConfigError {
        /// A path-like option was empty, oversized, or contained controls.
        InvalidPath,
        /// The explicit override did not point to a readable regular file.
        OverrideMissing(&'static str),
        /// No configuration file was found in any reviewed location.
        NotFound(&'static str),
        /// A log-filter string was empty, oversized, or contained controls.
        InvalidLogFilter,
        /// The process environment could not be inspected.
        Environment,
    }

    impl fmt::Display for ConfigError {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                Self::InvalidPath => formatter.write_str(
                    "path must be non-empty, bounded, and free of control characters",
                ),
                Self::OverrideMissing(name) => write!(
                    formatter,
                    "{name} does not point to a readable regular file"
                ),
                Self::NotFound(name) => write!(
                    formatter,
                    "cannot locate startup configuration; set {name} to its path"
                ),
                Self::InvalidLogFilter => formatter.write_str(
                    "log filter must be non-empty, bounded, and free of control characters",
                ),
                Self::Environment => {
                    formatter.write_str("failed to inspect the process environment")
                }
            }
        }
    }

    impl Error for ConfigError {}

    /// Converts a user-supplied filesystem path after conservative validation.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::InvalidPath`] for empty, control-bearing, or
    /// excessively large values.
    pub fn validate_path(value: &str) -> Result<PathBuf, ConfigError> {
        let value = value.trim();
        if value.is_empty()
            || value.len() > 4096
            || value.chars().any(char::is_control)
        {
            return Err(ConfigError::InvalidPath);
        }
        Ok(PathBuf::from(value))
    }

    /// Validates a tracing-filter expression before an SDK-specific parser sees it.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::InvalidLogFilter`] when the text is empty,
    /// larger than 1024 bytes, or contains control characters.
    pub fn validate_log_filter_text(value: &str) -> Result<&str, ConfigError> {
        let value = value.trim();
        if value.is_empty()
            || value.len() > 1024
            || value.chars().any(char::is_control)
        {
            return Err(ConfigError::InvalidLogFilter);
        }
        Ok(value)
    }

    /// Returns option names without ever echoing their `=value` payloads.
    #[must_use]
    pub fn redacted_option_names(options: &[String]) -> String {
        options
            .iter()
            .map(|option| {
                option
                    .split_once('=')
                    .map_or(option.as_str(), |(name, _)| name)
            })
            .collect::<Vec<_>>()
            .join(", ")
    }

    /// Finds one startup configuration through the reviewed fleet search order.
    ///
    /// Search order:
    ///
    /// 1. the explicit environment override;
    /// 2. the current working directory;
    /// 3. the executable directory;
    /// 4. `../share/<install_share_subdir>` beside the executable.
    ///
    /// # Errors
    ///
    /// Returns a redacted error when the override is invalid or no candidate is
    /// a regular file.
    pub fn resolve_config_path(spec: ConfigPathSpec) -> Result<PathBuf, ConfigError> {
        if let Some(raw) = std::env::var_os(spec.override_env).filter(|value| !value.is_empty()) {
            let path = PathBuf::from(raw);
            if path.is_file() {
                return Ok(path);
            }
            return Err(ConfigError::OverrideMissing(spec.override_env));
        }

        let mut candidates = Vec::with_capacity(3);
        if let Ok(current) = std::env::current_dir() {
            candidates.push(current.join(spec.file_name));
        }
        if let Ok(executable) = std::env::current_exe() {
            if let Some(parent) = executable.parent() {
                candidates.push(parent.join(spec.file_name));
                candidates.push(
                    parent
                        .join("../share")
                        .join(spec.install_share_subdir)
                        .join(spec.file_name),
                );
            }
        }

        candidates
            .into_iter()
            .find(|candidate| candidate.is_file())
            .ok_or(ConfigError::NotFound(spec.override_env))
    }

    /// Returns whether a candidate is a regular file without following the
    /// caller into file contents.
    #[must_use]
    pub fn readable_regular_file(path: &Path) -> bool {
        path.is_file()
    }

    /// Maps a configuration error to `io::ErrorKind::InvalidInput` for servers
    /// whose public startup API already returns `io::Error`.
    #[must_use]
    pub fn invalid_input(error: ConfigError) -> io::Error {
        io::Error::new(io::ErrorKind::InvalidInput, error)
    }
}

/// Secret-free resource-attribute parsing shared by OTEL SDK adapters.
pub mod telemetry {
    use ore_mcp_safety::{is_sensitive_key, valid_attribute_key, valid_attribute_value};

    /// Maximum raw `OTEL_RESOURCE_ATTRIBUTES` bytes accepted by the parser.
    pub const MAX_RESOURCE_ATTRIBUTE_BYTES: usize = 8192;
    /// Maximum number of accepted custom attributes.
    pub const MAX_RESOURCE_ATTRIBUTE_PAIRS: usize = 64;

    /// Standard process-environment mappings used by the MCP fleet.
    pub const STANDARD_RESOURCE_ENV: [(&str, &str); 5] = [
        ("DEPLOYMENT_ENV", "deployment.environment"),
        ("POD_NAMESPACE", "k8s.namespace.name"),
        ("POD_NAME", "k8s.pod.name"),
        ("NODE_NAME", "k8s.node.name"),
        ("HOSTNAME", "host.name"),
    ];

    /// Returns whether a caller is attempting to override canonical identity.
    #[must_use]
    pub fn reserved_identity_key(key: &str) -> bool {
        matches!(
            key,
            "service.name" | "service.namespace" | "service.version"
        )
    }

    /// Parses bounded, printable, non-sensitive OTEL resource attributes.
    ///
    /// Invalid pairs are ignored rather than logged because their values may be
    /// sensitive. The output is capped at 64 entries and canonical service
    /// identity keys cannot be overridden.
    #[must_use]
    pub fn resource_attribute_pairs(raw: &str) -> Vec<(String, String)> {
        if raw.len() > MAX_RESOURCE_ATTRIBUTE_BYTES {
            return Vec::new();
        }
        raw.split(',')
            .filter_map(|pair| {
                let (key, value) = pair.split_once('=')?;
                let key = key.trim();
                let value = value.trim();
                if valid_attribute_key(key)
                    && valid_attribute_value(value)
                    && !is_sensitive_key(key)
                    && !reserved_identity_key(key)
                {
                    Some((key.to_string(), value.to_string()))
                } else {
                    None
                }
            })
            .take(MAX_RESOURCE_ATTRIBUTE_PAIRS)
            .collect()
    }

    /// Collects the standard environment attributes plus safe custom OTEL pairs.
    #[must_use]
    pub fn environment_resource_attributes() -> Vec<(String, String)> {
        let mut attributes = STANDARD_RESOURCE_ENV
            .iter()
            .filter_map(|(env_name, key)| {
                let value = std::env::var(env_name).ok()?;
                let value = value.trim();
                if valid_attribute_value(value) {
                    Some(((*key).to_string(), value.to_string()))
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();
        if let Ok(raw) = std::env::var("OTEL_RESOURCE_ATTRIBUTES") {
            attributes.extend(resource_attribute_pairs(&raw));
        }
        attributes
    }
}

/// Runtime identity and transport metadata shared by server entry points.
pub mod runtime {
    use std::{error::Error, fmt};

    use ore_mcp_safety::valid_attribute_value;

    /// Canonical stdio transport label used in logs and spans.
    pub const STDIO_TRANSPORT: &str = "stdio";

    /// Validated, secret-free identity for one MCP server process.
    #[derive(Clone, Debug, Eq, PartialEq)]
    pub struct ServerIdentity {
        service_name: String,
        service_namespace: String,
        transport: String,
    }

    impl ServerIdentity {
        /// Constructs a validated identity for a stdio MCP server.
        ///
        /// # Errors
        ///
        /// Returns [`IdentityError`] for empty, oversized, or control-bearing
        /// names.
        pub fn stdio(
            service_name: impl Into<String>,
            service_namespace: impl Into<String>,
        ) -> Result<Self, IdentityError> {
            Self::new(service_name, service_namespace, STDIO_TRANSPORT)
        }

        /// Constructs a validated identity for an explicit transport.
        ///
        /// # Errors
        ///
        /// Returns [`IdentityError`] when any component is not a bounded,
        /// printable telemetry value or the transport is not a portable token.
        pub fn new(
            service_name: impl Into<String>,
            service_namespace: impl Into<String>,
            transport: impl Into<String>,
        ) -> Result<Self, IdentityError> {
            let service_name = service_name.into();
            let service_namespace = service_namespace.into();
            let transport = transport.into();
            if !valid_component(&service_name) {
                return Err(IdentityError::ServiceName);
            }
            if !valid_component(&service_namespace) {
                return Err(IdentityError::ServiceNamespace);
            }
            if transport.is_empty()
                || transport.len() > 32
                || !transport
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
            {
                return Err(IdentityError::Transport);
            }
            Ok(Self {
                service_name,
                service_namespace,
                transport,
            })
        }

        /// Returns the canonical service name.
        #[must_use]
        pub fn service_name(&self) -> &str {
            &self.service_name
        }

        /// Returns the canonical service namespace.
        #[must_use]
        pub fn service_namespace(&self) -> &str {
            &self.service_namespace
        }

        /// Returns the transport label.
        #[must_use]
        pub fn transport(&self) -> &str {
            &self.transport
        }

        /// Returns stable, low-cardinality startup attributes.
        #[must_use]
        pub fn startup_attributes(&self) -> [(&'static str, &str); 3] {
            [
                ("service.name", self.service_name()),
                ("service.namespace", self.service_namespace()),
                ("transport", self.transport()),
            ]
        }
    }

    fn valid_component(value: &str) -> bool {
        value.len() <= 128 && valid_attribute_value(value)
    }

    /// Invalid server-identity component.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub enum IdentityError {
        /// Invalid service name.
        ServiceName,
        /// Invalid service namespace.
        ServiceNamespace,
        /// Invalid transport token.
        Transport,
    }

    impl fmt::Display for IdentityError {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                Self::ServiceName => formatter.write_str("invalid MCP service name"),
                Self::ServiceNamespace => {
                    formatter.write_str("invalid MCP service namespace")
                }
                Self::Transport => formatter.write_str("invalid MCP transport label"),
            }
        }
    }

    impl Error for IdentityError {}
}

#[cfg(test)]
mod tests {
    use super::{config, runtime, telemetry};

    #[test]
    fn option_values_are_never_echoable() {
        let options = vec![
            "--api-key=supersecret".to_string(),
            "--root=/tmp/repo".to_string(),
            "--flag".to_string(),
        ];
        assert_eq!(
            config::redacted_option_names(&options),
            "--api-key, --root, --flag"
        );
    }

    #[test]
    fn path_and_log_filter_validation_is_bounded() {
        assert!(config::validate_path(" /tmp/repo ").is_ok());
        assert!(config::validate_path("bad\npath").is_err());
        assert!(config::validate_log_filter_text("info,hyper=warn").is_ok());
        assert!(config::validate_log_filter_text("bad\nfilter").is_err());
    }

    #[test]
    fn telemetry_pairs_reject_secrets_and_identity_spoofing() {
        let pairs = telemetry::resource_attribute_pairs(
            "team=simulation,api.token=nope,service.name=spoof,cloud.region=us-east-1",
        );
        assert_eq!(
            pairs,
            vec![
                ("team".to_string(), "simulation".to_string()),
                ("cloud.region".to_string(), "us-east-1".to_string()),
            ]
        );
    }

    #[test]
    fn telemetry_pair_count_and_raw_input_are_bounded() {
        let raw = (0..100)
            .map(|index| format!("key{index}=value"))
            .collect::<Vec<_>>()
            .join(",");
        assert_eq!(
            telemetry::resource_attribute_pairs(&raw).len(),
            telemetry::MAX_RESOURCE_ATTRIBUTE_PAIRS
        );
        assert!(telemetry::resource_attribute_pairs(&"x".repeat(8193)).is_empty());
    }

    #[test]
    fn runtime_identity_is_stable_and_low_cardinality() {
        let identity = runtime::ServerIdentity::stdio("example-mcp", "example-org")
            .expect("valid identity");
        assert_eq!(identity.transport(), runtime::STDIO_TRANSPORT);
        assert_eq!(
            identity.startup_attributes(),
            [
                ("service.name", "example-mcp"),
                ("service.namespace", "example-org"),
                ("transport", "stdio"),
            ]
        );
        assert!(runtime::ServerIdentity::stdio("bad\nname", "org").is_err());
        assert!(runtime::ServerIdentity::new("name", "org", "bad transport").is_err());
    }
}
