#![forbid(unsafe_code)]
//! Validated, product-neutral contracts for the read-only Zed dependency-graph MCP tool.
//!
//! Product repositories retain ownership of their organization, repository, package,
//! and dependency coordinates. This crate owns only bounded validation, the stable
//! structured representation, the closed-world tool descriptor, and the standard MCP
//! text-plus-structured result shape.

use std::{collections::BTreeSet, error::Error, fmt};

use serde_json::{json, Value};

/// Stable MCP tool name used by dependency-graph servers.
pub const TOOL_NAME: &str = "zed_dependency_graph";

/// Canonical directory where Zed dependencies materialize in consumer repositories.
pub const MATERIALIZATION_DIRECTORY: &str = ".vendor/.zed";

/// Canonical command for adopting an existing package gitlink into Zed ownership.
pub const ADOPTION_COMMAND: &str = "zed overtake --git-submodules";

const MAX_IDENTITY_BYTES: usize = 256;
const MAX_DEPENDENCIES: usize = 128;

/// A validated dependency graph for one product-owned MCP server.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DependencyGraph {
    organization: String,
    repository: String,
    package: String,
    dependencies: Vec<String>,
}

impl DependencyGraph {
    /// Construct a validated graph from product-owned package coordinates.
    ///
    /// # Errors
    ///
    /// Returns an error when an identity is empty, unbounded, malformed, outside the
    /// declared organization, duplicated, or when the dependency set is empty or too
    /// large.
    pub fn new<I, S>(
        organization: impl Into<String>,
        repository: impl Into<String>,
        package: impl Into<String>,
        dependencies: I,
    ) -> Result<Self, DependencyGraphError>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let organization = organization.into();
        let repository = repository.into();
        let package = package.into();

        if !is_component(&organization) {
            return Err(DependencyGraphError::new(
                "organization must be one bounded repository-coordinate component",
            ));
        }
        let Some((repository_owner, _)) = coordinate_parts(&repository) else {
            return Err(DependencyGraphError::new(
                "repository must be a bounded owner/name coordinate",
            ));
        };
        if repository_owner != organization {
            return Err(DependencyGraphError::new(
                "repository owner must equal the declared organization",
            ));
        }
        if !is_component(&package) {
            return Err(DependencyGraphError::new(
                "package must be one bounded package-name component",
            ));
        }

        let mut seen = BTreeSet::new();
        let mut validated = Vec::new();
        for (index, dependency) in dependencies.into_iter().enumerate() {
            if index >= MAX_DEPENDENCIES {
                return Err(DependencyGraphError::new(
                    "dependency graph exceeds the maximum package count",
                ));
            }
            let dependency = dependency.into();
            if coordinate_parts(&dependency).is_none() {
                return Err(DependencyGraphError::new(format!(
                    "dependency at index {index} is not a bounded owner/name coordinate"
                )));
            }
            if !seen.insert(dependency.clone()) {
                return Err(DependencyGraphError::new(format!(
                    "dependency at index {index} repeats an existing coordinate"
                )));
            }
            validated.push(dependency);
        }
        if validated.is_empty() {
            return Err(DependencyGraphError::new(
                "dependency graph must contain at least one package",
            ));
        }

        Ok(Self {
            organization,
            repository,
            package,
            dependencies: validated,
        })
    }

    /// Return the product organization.
    #[must_use]
    pub fn organization(&self) -> &str {
        &self.organization
    }

    /// Return the canonical owner/name repository coordinate.
    #[must_use]
    pub fn repository(&self) -> &str {
        &self.repository
    }

    /// Return the package identity exposed by the server.
    #[must_use]
    pub fn package(&self) -> &str {
        &self.package
    }

    /// Return the validated, unique dependency coordinates in declaration order.
    #[must_use]
    pub fn dependencies(&self) -> &[String] {
        &self.dependencies
    }

    /// Build the stable structured dependency-graph payload.
    #[must_use]
    pub fn structured_content(&self) -> Value {
        json!({
            "organization": self.organization,
            "repository": self.repository,
            "package": self.package,
            "materializationDirectory": MATERIALIZATION_DIRECTORY,
            "dependencies": self.dependencies,
            "submoduleInterop": {
                "gitAuthority": "exact committed checkout and source transport",
                "zedAuthority": "package identity, dependency intent, materialization, and lock provenance",
                "adoptionCommand": ADOPTION_COMMAND
            }
        })
    }

    /// Build the standard MCP text-plus-structured successful tool result.
    #[must_use]
    pub fn tool_result(&self) -> Value {
        let structured_content = self.structured_content();
        let text = serde_json::to_string_pretty(&structured_content)
            .expect("serde_json::Value serialization is infallible");
        json!({
            "content": [{"type": "text", "text": text}],
            "structuredContent": structured_content,
            "isError": false
        })
    }
}

/// Return the closed-world MCP tool descriptor for [`TOOL_NAME`].
#[must_use]
pub fn tool_descriptor() -> Value {
    json!({
        "name": TOOL_NAME,
        "title": "Zed dependency graph",
        "description": "Return canonical package dependencies and Git-submodule ownership rules.",
        "inputSchema": {
            "type": "object",
            "properties": {},
            "additionalProperties": false
        },
        "outputSchema": {
            "type": "object",
            "additionalProperties": false,
            "required": [
                "organization",
                "repository",
                "package",
                "materializationDirectory",
                "dependencies",
                "submoduleInterop"
            ],
            "properties": {
                "organization": {"type": "string", "minLength": 1, "maxLength": MAX_IDENTITY_BYTES},
                "repository": {"type": "string", "minLength": 3, "maxLength": MAX_IDENTITY_BYTES},
                "package": {"type": "string", "minLength": 1, "maxLength": MAX_IDENTITY_BYTES},
                "materializationDirectory": {"type": "string", "const": MATERIALIZATION_DIRECTORY},
                "dependencies": {
                    "type": "array",
                    "minItems": 1,
                    "maxItems": MAX_DEPENDENCIES,
                    "uniqueItems": true,
                    "items": {"type": "string", "minLength": 3, "maxLength": MAX_IDENTITY_BYTES}
                },
                "submoduleInterop": {
                    "type": "object",
                    "additionalProperties": false,
                    "required": ["gitAuthority", "zedAuthority", "adoptionCommand"],
                    "properties": {
                        "gitAuthority": {"type": "string"},
                        "zedAuthority": {"type": "string"},
                        "adoptionCommand": {"type": "string", "const": ADOPTION_COMMAND}
                    }
                }
            }
        }
    })
}

/// Validation failure returned while constructing a [`DependencyGraph`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DependencyGraphError {
    message: String,
}

impl DependencyGraphError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for DependencyGraphError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl Error for DependencyGraphError {}

fn coordinate_parts(value: &str) -> Option<(&str, &str)> {
    if value.len() > MAX_IDENTITY_BYTES {
        return None;
    }
    let (owner, name) = value.split_once('/')?;
    if name.contains('/') || !is_component(owner) || !is_component(name) {
        return None;
    }
    Some((owner, name))
}

fn is_component(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_IDENTITY_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_graph() -> DependencyGraph {
        DependencyGraph::new(
            "example-org",
            "example-org/example-mcp-server.rs",
            "example-mcp-server",
            [
                "example-org/example-clients",
                "example-org/example-interfaces",
                "shared-auth/shared-auth-clients",
            ],
        )
        .expect("sample graph should be valid")
    }

    #[test]
    fn structured_and_text_results_match() {
        let graph = sample_graph();
        let result = graph.tool_result();
        let text = result["content"][0]["text"]
            .as_str()
            .expect("tool text should be a string");
        let parsed: Value = serde_json::from_str(text).expect("tool text should be JSON");

        assert_eq!(parsed, result["structuredContent"]);
        assert_eq!(result["isError"], false);
        assert_eq!(
            result["structuredContent"]["materializationDirectory"],
            MATERIALIZATION_DIRECTORY
        );
        assert_eq!(
            result["structuredContent"]["submoduleInterop"]["adoptionCommand"],
            ADOPTION_COMMAND
        );
    }

    #[test]
    fn descriptor_is_closed_world() {
        let descriptor = tool_descriptor();

        assert_eq!(descriptor["name"], TOOL_NAME);
        assert_eq!(descriptor["inputSchema"]["additionalProperties"], false);
        assert_eq!(descriptor["outputSchema"]["additionalProperties"], false);
        assert_eq!(
            descriptor["outputSchema"]["properties"]["dependencies"]["uniqueItems"],
            true
        );
    }

    #[test]
    fn repository_must_belong_to_organization() {
        let error = DependencyGraph::new(
            "example-org",
            "other-org/example-mcp-server.rs",
            "example-mcp-server",
            ["example-org/example-clients"],
        )
        .expect_err("cross-organization repository should be rejected");

        assert!(error.to_string().contains("repository owner"));
    }

    #[test]
    fn duplicate_dependency_is_rejected() {
        let error = DependencyGraph::new(
            "example-org",
            "example-org/example-mcp-server.rs",
            "example-mcp-server",
            ["example-org/example-clients", "example-org/example-clients"],
        )
        .expect_err("duplicate package should be rejected");

        assert!(error.to_string().contains("repeats"));
    }

    #[test]
    fn malformed_coordinate_is_rejected() {
        let error = DependencyGraph::new(
            "example-org",
            "example-org/example-mcp-server.rs",
            "example-mcp-server",
            ["example-org/not valid"],
        )
        .expect_err("whitespace-bearing package should be rejected");

        assert!(error.to_string().contains("index 0"));
    }
}
