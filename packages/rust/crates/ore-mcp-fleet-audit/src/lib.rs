//! Verify that a consumer repository's `contracts/mcp-fleet.json` security
//! claims actually hold in its source.
//!
//! The fleet schema pins every security property to `true`/`false` by `const`,
//! so build admission proves only that a manifest *says* the right words. This
//! crate closes that gap: it reads the claims, then reads the tool definitions
//! the server really exposes, and reports where the two disagree.
//!
//! Extraction is deliberately conservative. A tool schema is only considered
//! when a `"inputSchema"` key is followed by a brace-balanced JSON object that
//! parses; anything else (an index expression in a test, a runtime-built value)
//! is skipped rather than guessed at, so a finding always points at a literal
//! schema a reader can see.

#![forbid(unsafe_code)]

use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};

/// Security properties a consumer declares in `contracts/mcp-fleet.json`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Claims {
    /// Every tool input schema forbids unknown properties.
    pub closed_tool_schemas: bool,
    /// Tool arguments never carry secret material.
    pub secret_tool_arguments: bool,
    /// The server exposes no general-purpose execution tool.
    pub generic_execution_allowed: bool,
}

impl Claims {
    /// Reads the claims from a consumer repository's fleet manifest.
    ///
    /// # Errors
    ///
    /// Returns an error when the manifest is missing, unreadable, not JSON, or
    /// missing its `security` block.
    pub fn from_repo(repo: &Path) -> Result<Self, AuditError> {
        let path = repo.join("contracts/mcp-fleet.json");
        let text = fs::read_to_string(&path).map_err(|source| AuditError::Manifest {
            path: path.clone(),
            source,
        })?;
        let value: serde_json::Value =
            serde_json::from_str(&text).map_err(|source| AuditError::ManifestJson {
                path: path.clone(),
                source,
            })?;
        let security = value
            .get("security")
            .ok_or_else(|| AuditError::ManifestShape {
                path: path.clone(),
                detail: "missing the `security` object".to_owned(),
            })?;
        let flag = |key: &str| -> Result<bool, AuditError> {
            security
                .get(key)
                .and_then(serde_json::Value::as_bool)
                .ok_or_else(|| AuditError::ManifestShape {
                    path: path.clone(),
                    detail: format!("security.{key} is missing or not a boolean"),
                })
        };
        Ok(Self {
            closed_tool_schemas: flag("closedToolSchemas")?,
            secret_tool_arguments: flag("secretToolArguments")?,
            generic_execution_allowed: flag("genericExecutionAllowed")?,
        })
    }
}

/// One disagreement between a declared claim and the source.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Finding {
    /// Repository-relative file the schema was found in.
    pub file: PathBuf,
    /// 1-indexed line of the offending schema.
    pub line: usize,
    /// Which claim the source contradicts.
    pub claim: &'static str,
    /// What the source does instead.
    pub detail: String,
}

impl fmt::Display for Finding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}:{}: {} — {}",
            self.file.display(),
            self.line,
            self.claim,
            self.detail
        )
    }
}

/// Why an audit could not be completed.
#[derive(Debug)]
pub enum AuditError {
    /// The fleet manifest could not be read.
    Manifest {
        /// Manifest path that failed to read.
        path: PathBuf,
        /// Underlying I/O error.
        source: std::io::Error,
    },
    /// The fleet manifest was not valid JSON.
    ManifestJson {
        /// Manifest path that failed to parse.
        path: PathBuf,
        /// Underlying parse error.
        source: serde_json::Error,
    },
    /// The fleet manifest lacked a property the audit needs.
    ManifestShape {
        /// Manifest path with the unexpected shape.
        path: PathBuf,
        /// What was missing.
        detail: String,
    },
    /// The source tree could not be walked.
    Source {
        /// Directory that failed to read.
        path: PathBuf,
        /// Underlying I/O error.
        source: std::io::Error,
    },
}

impl fmt::Display for AuditError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Manifest { path, source } => {
                write!(f, "cannot read {}: {source}", path.display())
            }
            Self::ManifestJson { path, source } => {
                write!(f, "{} is not valid JSON: {source}", path.display())
            }
            Self::ManifestShape { path, detail } => {
                write!(f, "{} {detail}", path.display())
            }
            Self::Source { path, source } => {
                write!(f, "cannot read {}: {source}", path.display())
            }
        }
    }
}

impl std::error::Error for AuditError {}

/// Property names that must never appear as tool arguments.
const SECRET_ARGUMENT_NAMES: &[&str] = &[
    "token",
    "secret",
    "password",
    "apikey",
    "api_key",
    "credential",
    "privatekey",
    "private_key",
];

/// Tool-name fragments that indicate general-purpose execution.
const EXECUTION_TOOL_NAMES: &[&str] = &["exec", "shell", "eval", "run_command", "spawn", "system"];

/// Audits one consumer repository, returning every claim the source contradicts.
///
/// # Errors
///
/// Returns an error when the manifest cannot be read or the source tree cannot
/// be walked. A repository whose claims all hold yields an empty vector.
pub fn audit(repo: &Path) -> Result<Vec<Finding>, AuditError> {
    let claims = Claims::from_repo(repo)?;
    let mut sources = Vec::new();
    collect_rust_sources(&repo.join("src"), &mut sources)?;
    sources.sort();

    let mut findings = Vec::new();
    let mut literal_count = 0usize;
    let mut corpus = String::new();
    for path in sources {
        let Ok(text) = fs::read_to_string(&path) else {
            continue;
        };
        let relative = path.strip_prefix(repo).unwrap_or(&path).to_path_buf();
        literal_count += literal_schemas(&text).len();
        corpus.push_str(&text);
        findings.extend(audit_text(&text, &relative, claims));
    }

    if claims.closed_tool_schemas {
        if let Some(detail) = unverified_surface(repo, literal_count, &corpus) {
            findings.push(Finding {
                file: PathBuf::from("Cargo.toml"),
                line: 1,
                claim: "closedToolSchemas",
                detail,
            });
        }
    }

    findings.sort_by(|a, b| (&a.file, a.line).cmp(&(&b.file, b.line)));
    Ok(findings)
}

/// Reports why a repository's schema closure could not be verified, if so.
///
/// Absence of a literal schema is not compliance. A repository either writes
/// schemas here, delegates its whole tool surface to a reviewed shared runtime
/// that is audited in its own repository, or derives schemas from Rust types —
/// in which case closure comes from `#[serde(deny_unknown_fields)]`. Anything
/// else is unverified, and `failClosedEvidence` in the fleet contract means
/// unverified is reported rather than waved through.
fn unverified_surface(repo: &Path, literal_count: usize, corpus: &str) -> Option<String> {
    let manifest = fs::read_to_string(repo.join("Cargo.toml")).unwrap_or_default();
    unverified_surface_in(&manifest, literal_count, corpus)
}

/// Filesystem-free core of [`unverified_surface`].
fn unverified_surface_in(manifest: &str, literal_count: usize, corpus: &str) -> Option<String> {
    if literal_count > 0 {
        return None;
    }
    if manifest.contains("ore-mcp-org-server") || manifest.contains("ore-mcp-bootstrap") {
        return None;
    }
    if manifest.contains("rmcp") {
        return if corpus.contains("deny_unknown_fields") {
            None
        } else {
            Some(
                "tool schemas are derived by rmcp/schemars, but no argument type uses \
                 #[serde(deny_unknown_fields)], so unknown properties are accepted"
                    .to_owned(),
            )
        };
    }
    if corpus.trim().is_empty() {
        return Some(
            "this repository declares fleet security claims but implements no tool surface yet; \
             implement the server or remove contracts/mcp-fleet.json until it exists"
                .to_owned(),
        );
    }
    Some(
        "no tool schema evidence found: this repository writes no literal schema, depends on no \
         reviewed shared runtime, and derives no schema from types"
            .to_owned(),
    )
}

/// Audits a single source file's text. Exposed for tests and reuse.
#[must_use]
pub fn audit_text(text: &str, file: &Path, claims: Claims) -> Vec<Finding> {
    let mut findings = Vec::new();

    for (offset, schema) in literal_schemas(text) {
        let line = line_of(text, offset);
        if claims.closed_tool_schemas && schema.get("additionalProperties") != Some(&false.into()) {
            findings.push(Finding {
                file: file.to_path_buf(),
                line,
                claim: "closedToolSchemas",
                detail: "tool input schema does not set `additionalProperties: false`".to_owned(),
            });
        }
        if !claims.secret_tool_arguments {
            if let Some(properties) = schema
                .get("properties")
                .and_then(serde_json::Value::as_object)
            {
                for key in properties.keys() {
                    let normalized = key.to_ascii_lowercase();
                    if SECRET_ARGUMENT_NAMES
                        .iter()
                        .any(|needle| normalized.contains(needle))
                    {
                        findings.push(Finding {
                            file: file.to_path_buf(),
                            line,
                            claim: "secretToolArguments",
                            detail: format!("tool argument `{key}` names secret material"),
                        });
                    }
                }
            }
        }
    }

    if !claims.generic_execution_allowed {
        for (offset, name) in tool_names(text) {
            let normalized = name.to_ascii_lowercase();
            if EXECUTION_TOOL_NAMES
                .iter()
                .any(|needle| normalized.contains(needle))
            {
                findings.push(Finding {
                    file: file.to_path_buf(),
                    line: line_of(text, offset),
                    claim: "genericExecutionAllowed",
                    detail: format!("tool `{name}` looks like general-purpose execution"),
                });
            }
        }
    }

    findings
}

/// Recursively collects `.rs` files, skipping `target` directories.
fn collect_rust_sources(dir: &Path, out: &mut Vec<PathBuf>) -> Result<(), AuditError> {
    if !dir.is_dir() {
        return Ok(());
    }
    let entries = fs::read_dir(dir).map_err(|source| AuditError::Source {
        path: dir.to_path_buf(),
        source,
    })?;
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            if path.file_name().is_some_and(|name| name == "target") {
                continue;
            }
            collect_rust_sources(&path, out)?;
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            out.push(path);
        }
    }
    Ok(())
}

/// Yields `(byte offset, parsed object)` for every literal `"inputSchema"` value.
fn literal_schemas(text: &str) -> Vec<(usize, serde_json::Value)> {
    let mut out = Vec::new();
    for (offset, _) in text.match_indices("\"inputSchema\"") {
        let rest = &text[offset + "\"inputSchema\"".len()..];
        let Some(colon) = rest.find(':') else {
            continue;
        };
        let after = &rest[colon + 1..];
        let trimmed = after.trim_start();
        if !trimmed.starts_with('{') {
            continue;
        }
        let skipped = after.len() - trimmed.len();
        let Some(end) = balanced_object_end(trimmed) else {
            continue;
        };
        if let Ok(value) = serde_json::from_str::<serde_json::Value>(&trimmed[..end]) {
            out.push((
                offset + "\"inputSchema\"".len() + colon + 1 + skipped,
                value,
            ));
        }
    }
    out
}

/// Yields `(byte offset, tool name)` for every literal `"name": "..."` pair.
fn tool_names(text: &str) -> Vec<(usize, String)> {
    let mut out = Vec::new();
    for (offset, _) in text.match_indices("\"name\"") {
        let rest = &text[offset + "\"name\"".len()..];
        let Some(colon) = rest.find(':') else {
            continue;
        };
        let after = rest[colon + 1..].trim_start();
        if !after.starts_with('"') {
            continue;
        }
        let Some(end) = after[1..].find('"') else {
            continue;
        };
        out.push((offset, after[1..=end].to_owned()));
    }
    out
}

/// Returns the byte index just past the object starting at `text[0] == '{'`.
fn balanced_object_end(text: &str) -> Option<usize> {
    let bytes = text.as_bytes();
    let mut depth = 0usize;
    let mut in_string = false;
    let mut escaped = false;
    for (index, byte) in bytes.iter().enumerate() {
        if in_string {
            if escaped {
                escaped = false;
            } else if *byte == b'\\' {
                escaped = true;
            } else if *byte == b'"' {
                in_string = false;
            }
            continue;
        }
        match byte {
            b'"' => in_string = true,
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    return Some(index + 1);
                }
            }
            _ => {}
        }
    }
    None
}

/// Converts a byte offset into a 1-indexed line number.
fn line_of(text: &str, offset: usize) -> usize {
    text[..offset.min(text.len())].matches('\n').count() + 1
}

#[cfg(test)]
mod tests {
    use super::*;

    const STRICT: Claims = Claims {
        closed_tool_schemas: true,
        secret_tool_arguments: false,
        generic_execution_allowed: false,
    };

    #[test]
    fn open_schema_is_reported() {
        let text = r#"json!({"name":"locations.get","inputSchema":{"type":"object","properties":{"slug":{"type":"string"}}}})"#;
        let findings = audit_text(text, Path::new("src/main.rs"), STRICT);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].claim, "closedToolSchemas");
    }

    #[test]
    fn closed_schema_is_accepted() {
        let text = r#"json!({"inputSchema":{"type":"object","additionalProperties":false,"properties":{}}})"#;
        assert!(audit_text(text, Path::new("src/main.rs"), STRICT).is_empty());
    }

    #[test]
    fn test_assertions_are_not_schemas() {
        // A test that indexes into a schema must not be mistaken for a schema
        // declaration; this is what made a naive grep report a false positive.
        let text = r#"assert_eq!(v["inputSchema"]["additionalProperties"], false);"#;
        assert!(audit_text(text, Path::new("src/lib.rs"), STRICT).is_empty());
    }

    #[test]
    fn secret_arguments_are_reported() {
        let text = r#"json!({"inputSchema":{"type":"object","additionalProperties":false,"properties":{"apiKey":{"type":"string"}}}})"#;
        let findings = audit_text(text, Path::new("src/main.rs"), STRICT);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].claim, "secretToolArguments");
    }

    #[test]
    fn execution_tools_are_reported() {
        let text = r#"json!({"name":"run_command","description":"runs a shell command"})"#;
        let findings = audit_text(text, Path::new("src/main.rs"), STRICT);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].claim, "genericExecutionAllowed");
    }

    #[test]
    fn nested_braces_do_not_truncate_a_schema() {
        let text = r#"json!({"inputSchema":{"type":"object","properties":{"a":{"type":"string"}},"additionalProperties":false}})"#;
        assert!(audit_text(text, Path::new("src/main.rs"), STRICT).is_empty());
    }

    #[test]
    fn a_repository_with_no_schema_evidence_fails_closed() {
        // Absence of a literal schema is not compliance: this is the case that
        // made a first version of this auditor pass 31 repositories vacuously.
        let detail = unverified_surface_in(
            "[dependencies]\nserde_json = \"1\"\n",
            0,
            "fn main() { serve(); }",
        );
        assert!(detail.is_some_and(|text| text.contains("no tool schema evidence")));
    }

    #[test]
    fn an_unimplemented_server_says_so() {
        // Several enrolled repositories are empty scaffolds. They still fail,
        // but the message has to name the real fix rather than imply the
        // schemas are wrong.
        let detail = unverified_surface_in("[dependencies]\nserde_json = \"1\"\n", 0, "   \n");
        assert!(detail.is_some_and(|text| text.contains("implements no tool surface yet")));
    }

    #[test]
    fn delegating_to_the_shared_runtime_is_verified_elsewhere() {
        let manifest = "[dependencies]\nore-mcp-org-server = { git = \"...\" }\n";
        assert!(unverified_surface_in(manifest, 0, "").is_none());
    }

    #[test]
    fn derived_schemas_need_deny_unknown_fields() {
        let manifest = "[dependencies]\nrmcp = \"2.2\"\nschemars = \"1\"\n";
        assert!(unverified_surface_in(manifest, 0, "#[derive(JsonSchema)]")
            .is_some_and(|text| text.contains("deny_unknown_fields")));
        assert!(
            unverified_surface_in(manifest, 0, "#[serde(deny_unknown_fields)]").is_none(),
            "a type that denies unknown fields is closed"
        );
    }

    #[test]
    fn line_numbers_are_one_indexed() {
        let text = "\n\njson!({\"inputSchema\":{\"type\":\"object\"}})";
        let findings = audit_text(text, Path::new("src/main.rs"), STRICT);
        assert_eq!(findings[0].line, 3);
    }
}
