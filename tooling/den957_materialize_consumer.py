#!/usr/bin/env python3
from pathlib import Path
import sys

REV = "a5c1ba9c50493ac625dd2fb175af21263d0d2801"
DEP = f'ore-mcp-bootstrap = {{ git = "https://github.com/ORESoftware/mcp-rust-libs", rev = "{REV}" }}'


def replace_function(source: str, name: str, replacement: str | None) -> str:
    start = source.find(f"fn {name}")
    if start < 0:
        return source
    brace = source.find("{", start)
    if brace < 0:
        raise SystemExit(f"missing body for {name}")
    depth = 0
    for index in range(brace, len(source)):
        if source[index] == "{":
            depth += 1
        elif source[index] == "}":
            depth -= 1
            if depth == 0:
                end = index + 1
                while end < len(source) and source[end] == "\n":
                    end += 1
                return source[:start] + (replacement or "") + source[end:]
    raise SystemExit(f"unbalanced body for {name}")


def materialize(repo: Path) -> None:
    manifest_path = repo / "Cargo.toml"
    manifest = manifest_path.read_text()
    if DEP not in manifest:
        marker = "[dependencies]\n"
        if marker not in manifest:
            raise SystemExit("Cargo.toml is missing [dependencies]")
        manifest = manifest.replace(marker, marker + DEP + "\n", 1)
    manifest_path.write_text(manifest)

    telemetry_path = repo / "src/telemetry.rs"
    telemetry = telemetry_path.read_text()
    if "ServerIdentity::stdio" not in telemetry:
        init_start = telemetry.find("pub fn init(")
        if init_start < 0:
            raise SystemExit("telemetry init function is missing")
        init_brace = telemetry.find("{", init_start)
        if init_brace < 0:
            raise SystemExit("telemetry init body is missing")
        identity = (
            "\n    let identity =\n"
            "        ore_mcp_bootstrap::runtime::ServerIdentity::stdio(service_name, service_namespace)\n"
            "            .expect(\"static MCP service identity must be valid\");\n"
            "    let service_name = identity.service_name();\n"
            "    let service_namespace = identity.service_namespace();"
        )
        telemetry = telemetry[: init_brace + 1] + identity + telemetry[init_brace + 1 :]

    raw_limit = (
        "MAX_RESOURCE_ATTRIBUTES_RAW_BYTES"
        if "MAX_RESOURCE_ATTRIBUTES_RAW_BYTES" in telemetry
        else "ore_mcp_bootstrap::telemetry::MAX_RESOURCE_ATTRIBUTE_BYTES"
    )
    pair_limit = (
        "MAX_RESOURCE_ATTRIBUTES"
        if "MAX_RESOURCE_ATTRIBUTES" in telemetry
        else "ore_mcp_bootstrap::telemetry::MAX_RESOURCE_ATTRIBUTE_PAIRS"
    )
    reserved = (
        "reserved_resource_attribute_key(&key)"
        if "fn reserved_resource_attribute_key" in telemetry
        else 'matches!(key.as_str(), "service.name" | "service.namespace" | "service.version" | "deployment.environment" | "k8s.namespace.name" | "k8s.pod.name" | "k8s.node.name" | "host.name")'
    )
    replacement = f'''fn resource_attribute_pairs(raw: &str) -> impl Iterator<Item = (String, String)> {{
    let mut attributes = Vec::new();
    if raw.len() > {raw_limit} {{
        return attributes.into_iter();
    }}
    let mut seen = std::collections::HashSet::new();
    for (key, value) in ore_mcp_bootstrap::telemetry::resource_attribute_pairs(raw) {{
        if attributes.len() >= {pair_limit} {{
            break;
        }}
        if !{reserved} && seen.insert(key.clone()) {{
            attributes.push((key, value));
        }}
    }}
    attributes.into_iter()
}}

'''
    telemetry = replace_function(telemetry, "resource_attribute_pairs", replacement)
    telemetry = replace_function(telemetry, "valid_attribute_key", None)
    telemetry = replace_function(telemetry, "sensitive_attribute_key", None)
    telemetry = telemetry.replace("    collections::HashSet,\n", "")
    telemetry_path.write_text(telemetry)

    tests = repo / "tests"
    tests.mkdir(exist_ok=True)
    (tests / "shared_bootstrap_contract.rs").write_text(
        f'''const MANIFEST: &str = include_str!("../Cargo.toml");
const TELEMETRY: &str = include_str!("../src/telemetry.rs");

#[test]
fn shared_bootstrap_dependency_is_immutable() {{
    assert!(MANIFEST.contains("ore-mcp-bootstrap"));
    assert!(MANIFEST.contains("rev = \\\"{REV}\\\""));
}}

#[test]
fn production_telemetry_delegates_version_neutral_policy() {{
    assert!(TELEMETRY.contains("ore_mcp_bootstrap::telemetry::resource_attribute_pairs"));
    assert!(TELEMETRY.contains("ore_mcp_bootstrap::runtime::ServerIdentity::stdio"));
    assert!(!TELEMETRY.contains("fn valid_attribute_key"));
    assert!(!TELEMETRY.contains("fn sensitive_attribute_key"));
}}
'''
    )


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("usage: den957_materialize_consumer.py REPOSITORY_PATH")
    materialize(Path(sys.argv[1]))
