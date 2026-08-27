use std::collections::{BTreeMap, BTreeSet};

use ore_mcp_bootstrap::telemetry::{
    reserved_identity_key, resource_attribute_pairs, STANDARD_RESOURCE_ENV,
};
use ore_mcp_safety::valid_attribute_value;

use crate::endpoint::MAX_RESOURCE_ATTRIBUTES;

/// Returns whether a resource key is owned by the shared runtime.
///
/// Custom `OTEL_RESOURCE_ATTRIBUTES` values cannot replace these fields.
#[must_use]
pub fn reserved_resource_key(key: &str) -> bool {
    reserved_identity_key(key)
        || key == "mcp.transport"
        || STANDARD_RESOURCE_ENV
            .iter()
            .any(|(_, resource_key)| *resource_key == key)
}

/// Builds deterministic, bounded resource attributes from an explicit snapshot.
///
/// The snapshot may contain the five fleet-standard environment names and an
/// `OTEL_RESOURCE_ATTRIBUTES` entry. Invalid values, sensitive keys, duplicate
/// keys, and runtime-owned fields are ignored without logging their contents.
#[must_use]
pub fn resource_attributes_from_snapshot(
    snapshot: &BTreeMap<String, String>,
) -> Vec<(String, String)> {
    let mut attributes = Vec::new();
    let mut seen = BTreeSet::new();

    for (environment_name, resource_key) in STANDARD_RESOURCE_ENV {
        if attributes.len() >= MAX_RESOURCE_ATTRIBUTES {
            break;
        }
        let Some(value) = snapshot.get(environment_name) else {
            continue;
        };
        let value = value.trim();
        if valid_attribute_value(value) && seen.insert(resource_key.to_string()) {
            attributes.push((resource_key.to_string(), value.to_string()));
        }
    }

    if let Some(raw) = snapshot.get("OTEL_RESOURCE_ATTRIBUTES") {
        for (key, value) in resource_attribute_pairs(raw) {
            if attributes.len() >= MAX_RESOURCE_ATTRIBUTES {
                break;
            }
            if !reserved_resource_key(&key) && seen.insert(key.clone()) {
                attributes.push((key, value));
            }
        }
    }

    attributes
}
