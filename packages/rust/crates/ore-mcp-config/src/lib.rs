//! Strict, secret-safe configuration resolution for ORESoftware MCP servers.
//!
//! This crate is deliberately an adapter rather than an argument parser. The
//! pinned `flags2env` client owns `.cli-flags.toml` audit, argv parsing, dotenv
//! channels, and typed coercion. This layer adds the fleet-wide invariants that
//! MCP servers need:
//!
//! - parser errors, unknown options, and positionals fail closed;
//! - caller-provided environment snapshots are merged in the documented source
//!   order without mutating process environment;
//! - sensitive-looking keys can never be supplied through argv;
//! - log filters reuse [`ore_mcp_bootstrap::config::validate_log_filter_text`]; and
//! - public diagnostics expose keys and counts, never configuration values.

#![forbid(unsafe_code)]

use std::{
    collections::{BTreeMap, BTreeSet},
    env, fmt,
    path::{Path, PathBuf},
};

use flags2env::{BundledFlags2Env, StructuredParse};
use ore_mcp_bootstrap::config::validate_log_filter_text;
use ore_mcp_safety::is_sensitive_key;
use serde::de::DeserializeOwned;

const ENVIRONMENT_ONLY_SUFFIXES: &[&str] = &[
    "DATABASE_URL",
    "REDIS_URL",
    "BROKER_URL",
    "AMQP_URL",
    "NATS_URL",
    "KAFKA_URL",
    "OTEL_EXPORTER_OTLP_HEADERS",
    "PASSPHRASE",
];
const MAX_DIAGNOSTIC_NAME_CHARS: usize = 96;

/// A strict configuration contract backed by one `.cli-flags.toml` file.
#[derive(Clone, Eq, PartialEq)]
pub struct StrictConfig {
    config_path: PathBuf,
}

impl StrictConfig {
    /// Creates a strict configuration contract for `config_path`.
    #[must_use]
    pub fn new(config_path: impl Into<PathBuf>) -> Self {
        Self {
            config_path: config_path.into(),
        }
    }

    /// Returns the configured `.cli-flags.toml` path.
    #[must_use]
    pub fn config_path(&self) -> &Path {
        &self.config_path
    }

    /// Audits the flags2env contract without parsing argv.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::ConfigPathNotUnicode`] when the path cannot cross
    /// the native boundary and [`ConfigError::AuditFailed`] when flags2env
    /// rejects the contract. Backend diagnostics are intentionally not exposed.
    pub fn audit(&self) -> Result<(), ConfigError> {
        let config_path = self.config_path_str()?;
        BundledFlags2Env::new()
            .audit_config(Some(config_path))
            .map_err(|_| ConfigError::AuditFailed)
    }

    /// Parses `argv` against an explicit caller-supplied environment snapshot.
    ///
    /// The returned values use the documented flags2env precedence: dotenv,
    /// caller environment, dotenv overrides, then argv-derived values.
    /// Process environment is not read or mutated by this method.
    ///
    /// # Errors
    ///
    /// Fails closed for an invalid contract, parser failure, parser-reported
    /// errors, unknown options, unexpected positionals, or sensitive argv keys.
    pub fn resolve(
        &self,
        argv: &[String],
        environment: &BTreeMap<String, String>,
    ) -> Result<ResolvedConfig, ConfigError> {
        self.audit()?;
        let config_path = self.config_path_str()?;
        let parsed = BundledFlags2Env::new()
            .parse_structured(argv, Some(config_path))
            .map_err(|_| ConfigError::ParseFailed)?;
        validate_structured(&parsed)?;
        Ok(merge_structured(parsed, environment))
    }

    /// Parses `argv` against a UTF-8 snapshot of the current process environment.
    ///
    /// # Errors
    ///
    /// In addition to [`StrictConfig::resolve`] errors, rejects the whole
    /// snapshot when any key or value is not valid UTF-8. The invalid values are
    /// never included in the error.
    pub fn resolve_process(&self, argv: &[String]) -> Result<ResolvedConfig, ConfigError> {
        let mut environment = BTreeMap::new();
        let mut non_unicode = 0usize;
        for (key, value) in env::vars_os() {
            match (key.into_string(), value.into_string()) {
                (Ok(key), Ok(value)) => {
                    environment.insert(key, value);
                }
                _ => non_unicode = non_unicode.saturating_add(1),
            }
        }
        if non_unicode > 0 {
            return Err(ConfigError::NonUnicodeEnvironment { count: non_unicode });
        }
        self.resolve(argv, &environment)
    }

    /// Coerces a previously resolved map into a typed Rust configuration.
    ///
    /// flags2env applies schema conversions to the already resolved map during
    /// this step. Validation messages and deserialization details are summarized by
    /// count or category so supplied values cannot escape through diagnostics.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::CoercionFailed`] when flags2env cannot produce the
    /// requested type.
    pub fn coerce<T>(&self, resolved: &ResolvedConfig) -> Result<T, ConfigError>
    where
        T: DeserializeOwned,
    {
        let config_path = self.config_path_str()?;
        BundledFlags2Env::new()
            .coerce(&resolved.values, Some(config_path))
            .map_err(|error| ConfigError::CoercionFailed {
                validation_errors: error.validation_errors().map(<[String]>::len),
            })
    }

    /// Resolves and coerces configuration in one operation.
    ///
    /// The resolved metadata is returned beside the typed value so callers can
    /// inspect command selection and source-order policy without reparsing.
    ///
    /// # Errors
    ///
    /// Returns any error from [`StrictConfig::resolve`] or
    /// [`StrictConfig::coerce`].
    pub fn resolve_typed<T>(
        &self,
        argv: &[String],
        environment: &BTreeMap<String, String>,
    ) -> Result<(ResolvedConfig, T), ConfigError>
    where
        T: DeserializeOwned,
    {
        let resolved = self.resolve(argv, environment)?;
        let typed = self.coerce(&resolved)?;
        Ok((resolved, typed))
    }

    fn config_path_str(&self) -> Result<&str, ConfigError> {
        self.config_path
            .to_str()
            .ok_or(ConfigError::ConfigPathNotUnicode)
    }
}

impl fmt::Debug for StrictConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StrictConfig")
            .field("config_path", &"<configured>")
            .finish()
    }
}

/// A strict configuration resolution with private values and public metadata.
#[derive(Clone, Eq, PartialEq)]
pub struct ResolvedConfig {
    values: BTreeMap<String, String>,
    provided_keys: BTreeSet<String>,
    source_order: BTreeMap<String, Vec<String>>,
    command: Option<String>,
    subcommands: Vec<String>,
}

impl ResolvedConfig {
    /// Returns one resolved value by environment key.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&str> {
        self.values.get(key).map(String::as_str)
    }

    /// Returns whether a resolved key exists.
    #[must_use]
    pub fn contains_key(&self, key: &str) -> bool {
        self.values.contains_key(key)
    }

    /// Returns resolved key names in deterministic order.
    pub fn keys(&self) -> impl Iterator<Item = &str> {
        self.values.keys().map(String::as_str)
    }

    /// Returns argv-derived key names in deterministic order.
    pub fn provided_keys(&self) -> impl Iterator<Item = &str> {
        self.provided_keys.iter().map(String::as_str)
    }

    /// Returns the selected command, if any.
    #[must_use]
    pub fn command(&self) -> Option<&str> {
        self.command.as_deref()
    }

    /// Returns selected subcommands in parser order.
    #[must_use]
    pub fn subcommands(&self) -> &[String] {
        &self.subcommands
    }

    /// Returns per-key source-order overrides in deterministic key order.
    #[must_use]
    pub fn source_order(&self) -> &BTreeMap<String, Vec<String>> {
        &self.source_order
    }

    /// Returns the number of resolved keys.
    #[must_use]
    pub fn len(&self) -> usize {
        self.values.len()
    }

    /// Returns whether no resolved values exist.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }

    /// Resolves and validates a tracing filter without exposing its raw value in
    /// an error.
    ///
    /// Empty or absent values use `default_filter`.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::InvalidLogFilter`] when the selected filter does
    /// not satisfy the shared bounded, control-free filter policy.
    pub fn validated_log_filter(
        &self,
        key: &str,
        default_filter: &str,
    ) -> Result<String, ConfigError> {
        let raw = self
            .get(key)
            .filter(|value| !value.trim().is_empty())
            .unwrap_or(default_filter);
        validate_log_filter_text(raw)
            .map(str::to_owned)
            .map_err(|_| ConfigError::InvalidLogFilter {
                key: sanitize_key(key),
            })
    }
}

impl fmt::Debug for ResolvedConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let keys: Vec<&str> = self.keys().collect();
        let provided_keys: Vec<&str> = self.provided_keys().collect();
        formatter
            .debug_struct("ResolvedConfig")
            .field("keys", &keys)
            .field("provided_keys", &provided_keys)
            .field("source_order", &self.source_order)
            .field("command", &self.command)
            .field("subcommands", &self.subcommands)
            .finish()
    }
}

/// Strict configuration failures that never retain supplied values.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ConfigError {
    /// The configured path cannot be represented as UTF-8 for flags2env.
    ConfigPathNotUnicode,
    /// The flags2env contract audit failed.
    AuditFailed,
    /// The flags2env parser could not produce a structured result.
    ParseFailed,
    /// The parser returned one or more errors.
    ParserErrors {
        /// Number of parser errors, without their potentially value-bearing text.
        count: usize,
    },
    /// One or more unknown option names were supplied.
    UnknownOptions {
        /// Sanitized option names with `=value` suffixes removed.
        options: Vec<String>,
    },
    /// One or more unexpected positional arguments were supplied.
    UnexpectedPositionals {
        /// Number of rejected positional arguments.
        count: usize,
    },
    /// Sensitive keys were supplied through argv instead of environment.
    SensitiveCliKeys {
        /// Sanitized environment key names; no values are retained.
        keys: Vec<String>,
    },
    /// The process environment contains non-UTF-8 keys or values.
    NonUnicodeEnvironment {
        /// Number of rejected environment entries.
        count: usize,
    },
    /// Typed flags2env coercion failed.
    CoercionFailed {
        /// Number of schema-validation messages when flags2env reported them.
        validation_errors: Option<usize>,
    },
    /// A selected log-filter key contained an invalid value.
    InvalidLogFilter {
        /// Sanitized environment key name; the filter value is not retained.
        key: String,
    },
}

impl fmt::Display for ConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ConfigPathNotUnicode => {
                formatter.write_str("configuration path is not valid UTF-8")
            }
            Self::AuditFailed => formatter.write_str("flags configuration audit failed"),
            Self::ParseFailed => formatter.write_str("flags configuration parsing failed"),
            Self::ParserErrors { count } => {
                write!(formatter, "flags parser reported {count} error(s)")
            }
            Self::UnknownOptions { options } => {
                write!(formatter, "unknown option(s): {}", options.join(", "))
            }
            Self::UnexpectedPositionals { count } => {
                write!(
                    formatter,
                    "rejected {count} unexpected positional argument(s)"
                )
            }
            Self::SensitiveCliKeys { keys } => write!(
                formatter,
                "sensitive key(s) must remain environment-only: {}",
                keys.join(", ")
            ),
            Self::NonUnicodeEnvironment { count } => {
                write!(
                    formatter,
                    "rejected {count} non-UTF-8 environment entry/entries"
                )
            }
            Self::CoercionFailed {
                validation_errors: Some(count),
            } => write!(
                formatter,
                "typed configuration coercion failed with {count} validation error(s)"
            ),
            Self::CoercionFailed {
                validation_errors: None,
            } => formatter.write_str("typed configuration coercion failed"),
            Self::InvalidLogFilter { key } => {
                write!(
                    formatter,
                    "configuration key {key} contains an invalid log filter"
                )
            }
        }
    }
}

impl std::error::Error for ConfigError {}

/// Returns whether `key` must remain environment-only under the default fleet
/// policy.
///
/// The shared bootstrap sensitive-key policy is extended for credential-bearing
/// connection URLs, passphrases, and OTLP header bundles. Ordinary non-secret
/// service base URLs such as `API_URL` remain eligible for explicit product
/// policy.
#[must_use]
pub fn is_environment_only_key(key: &str) -> bool {
    let normalized = normalize_key(key);
    is_sensitive_key(&normalized)
        || ENVIRONMENT_ONLY_SUFFIXES
            .iter()
            .any(|suffix| normalized == *suffix || normalized.ends_with(&format!("_{suffix}")))
}

fn validate_structured(parsed: &StructuredParse) -> Result<(), ConfigError> {
    if !parsed.errors.is_empty() {
        return Err(ConfigError::ParserErrors {
            count: parsed.errors.len(),
        });
    }
    if !parsed.unknown_options.is_empty() {
        let mut options: Vec<String> = parsed
            .unknown_options
            .iter()
            .map(|option| sanitize_option(option))
            .collect();
        options.sort();
        options.dedup();
        return Err(ConfigError::UnknownOptions { options });
    }
    if !parsed.extras.is_empty() {
        return Err(ConfigError::UnexpectedPositionals {
            count: parsed.extras.len(),
        });
    }

    let mut keys: Vec<String> = parsed
        .provided_flags
        .keys()
        .filter(|key| is_environment_only_key(key))
        .map(|key| sanitize_key(key))
        .collect();
    keys.sort();
    keys.dedup();
    if !keys.is_empty() {
        return Err(ConfigError::SensitiveCliKeys { keys });
    }
    Ok(())
}

fn merge_structured(
    parsed: StructuredParse,
    environment: &BTreeMap<String, String>,
) -> ResolvedConfig {
    let StructuredParse {
        provided_flags,
        dotenv,
        dotenv_overrides,
        source_order,
        command,
        subcommands,
        ..
    } = parsed;

    let provided_keys = provided_flags.keys().cloned().collect();
    let mut values = BTreeMap::new();
    values.extend(dotenv);
    values.extend(
        environment
            .iter()
            .map(|(key, value)| (key.clone(), value.clone())),
    );
    values.extend(dotenv_overrides);
    values.extend(provided_flags);

    ResolvedConfig {
        values,
        provided_keys,
        source_order: source_order.into_iter().collect(),
        command: (!command.is_empty()).then_some(command),
        subcommands,
    }
}

fn normalize_key(key: &str) -> String {
    key.replace('-', "_").to_ascii_uppercase()
}

fn sanitize_option(option: &str) -> String {
    let option_name = option.split_once('=').map_or(option, |(name, _)| name);
    sanitize_name(option_name, "<invalid-option>")
}

fn sanitize_key(key: &str) -> String {
    sanitize_name(key, "<invalid-key>")
}

fn sanitize_name(value: &str, fallback: &str) -> String {
    let mut sanitized = String::new();
    for character in value.chars().take(MAX_DIAGNOSTIC_NAME_CHARS) {
        if character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.' | ':') {
            sanitized.push(character);
        } else if character.is_whitespace() {
            break;
        } else {
            sanitized.push('_');
        }
    }
    if sanitized.is_empty() {
        fallback.to_string()
    } else {
        sanitized
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::HashMap, fs};

    use flags2env::StructuredParse;
    use serde::Deserialize;
    use tempfile::TempDir;

    use super::*;

    #[derive(Debug, Deserialize, Eq, PartialEq)]
    #[serde(rename_all = "SCREAMING_SNAKE_CASE")]
    struct TypedConfig {
        test_root: String,
        test_count: i64,
        rust_log: String,
    }

    fn contract() -> (TempDir, PathBuf) {
        let directory = TempDir::new().expect("create temporary contract directory");
        let path = directory.path().join(".cli-flags.toml");
        fs::write(
            &path,
            r#"
[parse]
allow_unknown = false

[flags.root]
env = "TEST_ROOT"
type = "string"

[flags.count]
env = "TEST_COUNT"
type = "integer"

[flags.log-filter]
env = "RUST_LOG"
type = "string"
default = "info,hyper=warn"
"#,
        )
        .expect("write flags contract");
        (directory, path)
    }

    #[test]
    fn resolves_and_coerces_without_mutating_environment() {
        let (_directory, path) = contract();
        let config = StrictConfig::new(path);
        let environment = BTreeMap::from([("TEST_ROOT".to_string(), "/srv/test".to_string())]);
        let argv = vec![
            "server".to_string(),
            "--count=7".to_string(),
            "--log-filter=debug,hyper=warn".to_string(),
        ];

        let (resolved, typed): (ResolvedConfig, TypedConfig) = config
            .resolve_typed(&argv, &environment)
            .expect("strict typed resolution succeeds");
        assert_eq!(resolved.get("TEST_ROOT"), Some("/srv/test"));
        assert_eq!(resolved.get("TEST_COUNT"), Some("7"));
        assert_eq!(
            resolved.validated_log_filter("RUST_LOG", "info").unwrap(),
            "debug,hyper=warn"
        );
        assert_eq!(
            typed,
            TypedConfig {
                test_root: "/srv/test".to_string(),
                test_count: 7,
                rust_log: "debug,hyper=warn".to_string(),
            }
        );
    }

    #[test]
    fn unknown_option_is_named_without_echoing_its_value() {
        let (_directory, path) = contract();
        let error = StrictConfig::new(path)
            .resolve(
                &[
                    "server".to_string(),
                    "--unknown=super-secret-value".to_string(),
                ],
                &BTreeMap::new(),
            )
            .expect_err("unknown option must fail");
        let display = error.to_string();
        assert!(matches!(error, ConfigError::UnknownOptions { .. }));
        assert!(display.contains("--unknown"));
        assert!(!display.contains("super-secret-value"));
    }

    #[test]
    fn positional_values_are_rejected_by_count_only() {
        let (_directory, path) = contract();
        let error = StrictConfig::new(path)
            .resolve(
                &["server".to_string(), "private/customer/path".to_string()],
                &BTreeMap::new(),
            )
            .expect_err("positional must fail");
        assert_eq!(error, ConfigError::UnexpectedPositionals { count: 1 });
        assert!(!error.to_string().contains("customer"));
    }

    #[test]
    fn sensitive_argv_keys_are_environment_only() {
        let mut provided_flags = HashMap::new();
        provided_flags.insert("DATABASE_URL".to_string(), "postgres://secret".to_string());
        provided_flags.insert("API_TOKEN".to_string(), "secret".to_string());
        let parsed = StructuredParse {
            provided_flags,
            ..StructuredParse::default()
        };
        let error = validate_structured(&parsed).expect_err("sensitive argv keys must fail");
        assert_eq!(
            error,
            ConfigError::SensitiveCliKeys {
                keys: vec!["API_TOKEN".to_string(), "DATABASE_URL".to_string()]
            }
        );
        let display = error.to_string();
        assert!(!display.contains("postgres://"));
        assert!(!display.contains("secret"));
    }

    #[test]
    fn channel_precedence_is_deterministic() {
        let parsed = StructuredParse {
            provided_flags: HashMap::from([
                ("ARGV".to_string(), "argv".to_string()),
                ("SHARED".to_string(), "argv".to_string()),
            ]),
            dotenv: HashMap::from([
                ("DOTENV".to_string(), "dotenv".to_string()),
                ("SHARED".to_string(), "dotenv".to_string()),
            ]),
            dotenv_overrides: HashMap::from([
                ("OVERRIDE".to_string(), "dotenv-override".to_string()),
                ("SHARED".to_string(), "dotenv-override".to_string()),
            ]),
            source_order: HashMap::from([(
                "SHARED".to_string(),
                vec!["dotenv".to_string(), "env".to_string(), "argv".to_string()],
            )]),
            command: "serve".to_string(),
            subcommands: vec!["stdio".to_string()],
            ..StructuredParse::default()
        };
        let environment = BTreeMap::from([
            ("ENV".to_string(), "environment".to_string()),
            ("SHARED".to_string(), "environment".to_string()),
        ]);

        let resolved = merge_structured(parsed, &environment);
        assert_eq!(resolved.get("DOTENV"), Some("dotenv"));
        assert_eq!(resolved.get("ENV"), Some("environment"));
        assert_eq!(resolved.get("OVERRIDE"), Some("dotenv-override"));
        assert_eq!(resolved.get("ARGV"), Some("argv"));
        assert_eq!(resolved.get("SHARED"), Some("argv"));
        assert_eq!(resolved.command(), Some("serve"));
        assert_eq!(resolved.subcommands(), ["stdio"]);
        assert!(resolved.provided_keys().any(|key| key == "SHARED"));
        assert_eq!(resolved.source_order()["SHARED"], ["dotenv", "env", "argv"]);
    }

    #[test]
    fn invalid_log_filter_never_appears_in_diagnostics() {
        let resolved = ResolvedConfig {
            values: BTreeMap::from([(
                "RUST_LOG".to_string(),
                "debug\nAuthorization: Bearer secret".to_string(),
            )]),
            provided_keys: BTreeSet::new(),
            source_order: BTreeMap::new(),
            command: None,
            subcommands: Vec::new(),
        };
        let error = resolved
            .validated_log_filter("RUST_LOG", "info")
            .expect_err("invalid filter must fail");
        assert_eq!(
            error,
            ConfigError::InvalidLogFilter {
                key: "RUST_LOG".to_string()
            }
        );
        assert!(!error.to_string().contains("Bearer"));
        assert!(!error.to_string().contains("secret"));
    }

    #[test]
    fn coercion_failure_is_summarized_without_raw_value() {
        let (_directory, path) = contract();
        let config = StrictConfig::new(path);
        let environment = BTreeMap::from([
            ("TEST_ROOT".to_string(), "/srv/test".to_string()),
            ("TEST_COUNT".to_string(), "not-a-number".to_string()),
        ]);
        let resolved = config
            .resolve(&["server".to_string()], &environment)
            .expect("explicit environment values are resolved before coercion");
        let error = config
            .coerce::<TypedConfig>(&resolved)
            .expect_err("integer coercion must fail");
        assert!(matches!(error, ConfigError::CoercionFailed { .. }));
        assert!(!error.to_string().contains("not-a-number"));
    }

    #[test]
    fn debug_output_lists_keys_but_never_values_or_paths() {
        let resolved = ResolvedConfig {
            values: BTreeMap::from([
                ("API_TOKEN".to_string(), "very-secret".to_string()),
                ("RUST_LOG".to_string(), "info".to_string()),
            ]),
            provided_keys: BTreeSet::from(["RUST_LOG".to_string()]),
            source_order: BTreeMap::new(),
            command: None,
            subcommands: Vec::new(),
        };
        let debug = format!("{resolved:?}");
        assert!(debug.contains("API_TOKEN"));
        assert!(debug.contains("RUST_LOG"));
        assert!(!debug.contains("very-secret"));

        let config = StrictConfig::new("/private/customer/.cli-flags.toml");
        let debug = format!("{config:?}");
        assert!(debug.contains("<configured>"));
        assert!(!debug.contains("customer"));
    }

    #[test]
    fn environment_only_detection_is_conservative_not_all_urls() {
        for key in [
            "API_TOKEN",
            "DATABASE_URL",
            "APP_REDIS_URL",
            "GPG_PASSPHRASE",
            "OTEL_EXPORTER_OTLP_HEADERS",
        ] {
            assert!(is_environment_only_key(key), "expected {key} to be secret");
        }
        for key in ["API_URL", "RUST_LOG", "ORG_ROOT", "SERVER_NAME"] {
            assert!(
                !is_environment_only_key(key),
                "expected {key} to remain product-policy controlled"
            );
        }
    }

    #[test]
    fn parser_errors_are_counted_without_retaining_messages() {
        let parsed = StructuredParse {
            errors: vec![
                "bad value secret-one".to_string(),
                "bad value secret-two".to_string(),
            ],
            ..StructuredParse::default()
        };
        let error = validate_structured(&parsed).expect_err("parser errors must fail");
        assert_eq!(error, ConfigError::ParserErrors { count: 2 });
        assert!(!error.to_string().contains("secret"));
    }
}
