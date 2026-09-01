#!/usr/bin/env python3
from __future__ import annotations

import copy
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path


PATH = Path(__file__).with_name("validate_mcp_fleet_profile.py")
SPEC = importlib.util.spec_from_file_location("mcp_fleet_profile", PATH)
assert SPEC is not None and SPEC.loader is not None
validator = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = validator
SPEC.loader.exec_module(validator)

REVISION = "a" * 40
SHARED_REVISION = "b" * 40
TEST_REVISION = "c" * 40
VERIFIED_AT = "2026-08-31T18:00:00Z"
CLIENTS = ("cursor", "openai", "anthropic", "gemini", "grok", "qwen")
PROVIDERS = (
    "github",
    "aws",
    "gcp",
    "supabase",
    "neon",
    "cloudflare",
    "k8s_cluster",
    "nats",
)
ORIGINS = {
    "github": "https://api.github.com",
    "aws": "aws-sdk://sts",
    "gcp": "gcp-sdk://application-default",
    "supabase": "https://example.supabase.co",
    "neon": "https://console.neon.tech",
    "cloudflare": "https://api.cloudflare.com",
    "k8s_cluster": "kubeconfig://oresoftware-k8s-cluster",
    "nats": "tls://nats.example.com",
}


def source_evidence(revision: str = REVISION) -> dict[str, str]:
    return {
        "kind": "source_test",
        "reference": "tests/parity.rs::parity_contract",
        "revision": revision,
        "verifiedAt": VERIFIED_AT,
    }


def annotations(read_only: bool = True) -> dict[str, bool]:
    return {
        "readOnlyHint": read_only,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    }


class McpFleetProfileTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.write("Cargo.lock", "# committed lock fixture\n")
        symbols: list[str] = []
        for provider in PROVIDERS:
            symbols.extend(
                [
                    f"struct {provider.title().replace('_', '')}Adapter;",
                    f"fn {provider}_identity() {{}}",
                    f"fn {provider}_inventory() {{}}",
                    f"fn fleet_tool_{provider}() {{}}",
                ]
            )
        symbols.append("fn fleet_posture() {}")
        self.write("src/integrations.rs", "\n".join(symbols) + "\n")
        self.write(
            "tests/parity.rs",
            "fn parity_contract() { let _ = \""
            + " ".join(
                [
                    *(f"{provider}_identity {provider}_inventory" for provider in PROVIDERS),
                    "fleet_posture",
                ]
            )
            + "\"; }\n",
        )
        self.profile = self.valid_profile()

    def tearDown(self) -> None:
        self.temp.cleanup()

    def write(self, path: str, text: str) -> None:
        target = self.root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8")

    def implementation(self, symbol: str) -> dict[str, str]:
        return {
            "module": "src/integrations.rs",
            "symbol": symbol,
            "test": "tests/parity.rs",
        }

    def valid_profile(self) -> dict[str, object]:
        integrations: list[dict[str, object]] = []
        for provider in PROVIDERS:
            integrations.append(
                {
                    "id": provider,
                    "role": "upstream_service",
                    "implementation": self.implementation(
                        f"{provider.title().replace('_', '')}Adapter"
                    ),
                    "configurationKeys": [f"EXAMPLE_{provider.upper()}_CONFIG"],
                    "allowedOrigins": [ORIGINS[provider]],
                    "scopes": [f"example:{provider}:read"],
                    "stateModel": [
                        "ready",
                        "not_configured",
                        "degraded",
                        "unauthorized",
                        "forbidden",
                    ],
                    "operations": [
                        {
                            "name": f"{provider}_identity",
                            "mode": "diagnostic",
                            "description": f"Resolve the configured Example identity boundary for {provider} without returning credentials.",
                            "organizationScope": "example",
                            "timeoutMs": 3000,
                            "outputMaxBytes": 4096,
                        },
                        {
                            "name": f"{provider}_inventory",
                            "mode": "read",
                            "description": f"Read the bounded Example-owned {provider} inventory under the declared least-privilege scope.",
                            "organizationScope": "example",
                            "timeoutMs": 5000,
                            "outputMaxBytes": 32768,
                        },
                    ],
                    "evidence": [source_evidence()],
                }
            )
        tools: list[dict[str, object]] = []
        for provider in PROVIDERS:
            tools.append(
                {
                    "name": f"example_{provider}_inventory",
                    "description": f"Read the bounded Example organization inventory from {provider} with explicit authority and failure semantics.",
                    "implementation": self.implementation(f"fleet_tool_{provider}"),
                    "integrations": [provider],
                    "annotations": annotations(),
                    "inputSchemaClosed": True,
                    "outputMaxBytes": 32768,
                }
            )
        tools.append(
            {
                "name": "fleet_posture",
                "description": "Compose GitHub repository and Kubernetes workload evidence for the Example deployment-readiness posture.",
                "implementation": self.implementation("fleet_posture"),
                "integrations": ["github", "k8s_cluster"],
                "annotations": annotations(),
                "inputSchemaClosed": True,
                "outputMaxBytes": 65536,
            }
        )
        return {
            "schemaVersion": 1,
            "identity": {
                "organization": "example",
                "repository": "example/example-mcp-server.rs",
                "revision": REVISION,
                "linearIssue": "DEN-965",
                "serverName": "example-mcp-server",
                "summary": "Organization-specific Example operations, deployment evidence, and provider diagnostics.",
            },
            "protocol": {
                "finalRevision": "2025-11-25",
                "transports": [
                    {
                        "kind": "stdio",
                        "enabled": True,
                        "authentication": "process_boundary",
                        "evidence": [source_evidence()],
                    },
                    {
                        "kind": "streamable_http",
                        "enabled": True,
                        "authentication": "oauth_2_1",
                        "endpointPath": "/mcp",
                        "evidence": [source_evidence()],
                    },
                ],
                "remoteAuthorization": {
                    "authority": "shared-auth",
                    "protectedResourceMetadata": True,
                    "wwwAuthenticateChallenge": True,
                    "audienceBound": True,
                    "authorizedClientValidated": True,
                    "realmValidated": True,
                    "noTokenPassthrough": True,
                    "exactHostPolicy": True,
                    "credentialedRedirectsDisabled": True,
                    "credentialedAmbientProxyDisabled": True,
                    "requestBodyMaxBytes": 1048576,
                    "responseBodyMaxBytes": 1048576,
                },
            },
            "clients": [
                {
                    "id": client,
                    "role": "mcp_client",
                    "transports": ["stdio", "streamable_http"],
                    "evidence": [source_evidence()],
                }
                for client in CLIENTS
            ],
            "integrations": integrations,
            "organizationSurface": {
                "repositories": ["example/example-mcp-server.rs", "example/example-api-server.rs"],
                "services": ["example-api-server", "example-mcp-server"],
                "kubernetesNamespaces": ["example"],
                "natsSubjects": ["example.events.>"],
                "runbooks": ["docs/deployment-readiness.md"],
                "tools": tools,
                "resources": [
                    {
                        "uri": "orgmap://example/repositories",
                        "description": "Canonical Example repository and service ownership map.",
                        "mimeType": "application/json",
                    },
                    {
                        "uri": "runbook://example/deployment-readiness",
                        "description": "Example deployment-readiness investigation and rollback guidance.",
                        "mimeType": "text/markdown",
                    },
                    {
                        "uri": "contract://example/provider-boundaries",
                        "description": "Example upstream provider authorities, scopes, and failure states.",
                        "mimeType": "application/json",
                    },
                ],
                "prompts": [
                    {
                        "name": "deployment_readiness",
                        "description": "Assess Example deployment readiness from repository and cluster evidence.",
                        "referencedTools": ["fleet_posture", "example_github_inventory"],
                    },
                    {
                        "name": "provider_degradation",
                        "description": "Diagnose one Example upstream degradation without exposing credentials.",
                        "referencedTools": ["example_supabase_inventory", "example_nats_inventory"],
                    },
                ],
                "composedReadTool": "fleet_posture",
            },
            "security": {
                "secretsEnvironmentOnly": True,
                "secretValuesExcluded": True,
                "stdoutProtocolOnly": True,
                "boundedLowCardinalityTelemetry": True,
                "exactOriginAllowlists": True,
                "credentialedRedirectsDisabled": True,
                "credentialedAmbientProxyDisabled": True,
                "mutationGate": {
                    "defaultDenied": True,
                    "runtimeAuthorization": True,
                    "allowlistedTargets": True,
                    "dryRun": True,
                    "targetBoundConfirmation": True,
                    "idempotency": True,
                    "boundedAudit": True,
                },
            },
            "evidence": {
                "repositoryTests": [source_evidence()],
                "testOrganization": {
                    "repository": "example-test/mcp-contract-e2e",
                    "productionRevision": REVISION,
                    "evidence": {
                        "kind": "test_org_run",
                        "reference": "https://github.com/example-test/mcp-contract-e2e/actions/runs/123",
                        "revision": TEST_REVISION,
                        "verifiedAt": VERIFIED_AT,
                    },
                },
                "sharedLibraryRevision": SHARED_REVISION,
                "lockfileCommitted": True,
            },
        }

    def errors(self, profile: dict[str, object] | None = None) -> list[str]:
        return validator.validate_profile(self.profile if profile is None else profile, self.root)

    def test_complete_profile_passes(self) -> None:
        self.assertEqual(self.errors(), [])

    def test_every_client_and_provider_is_required_exactly_once(self) -> None:
        profile = copy.deepcopy(self.profile)
        profile["clients"] = profile["clients"][:-1]
        profile["integrations"][1]["id"] = "github"
        errors = "\n".join(self.errors(profile))
        self.assertIn("expected exactly", errors)
        self.assertIn("duplicate id 'github'", errors)

    def test_provider_requires_real_read_and_source_operation(self) -> None:
        profile = copy.deepcopy(self.profile)
        github = profile["integrations"][0]
        github["operations"][1]["mode"] = "diagnostic"
        github["operations"][1]["name"] = "github_missing_operation"
        errors = "\n".join(self.errors(profile))
        self.assertIn("at least one real read is required", errors)
        self.assertIn("name is absent from implementation and focused test", errors)

    def test_no_op_tool_markers_and_missing_symbols_fail(self) -> None:
        profile = copy.deepcopy(self.profile)
        tool = profile["organizationSurface"]["tools"][0]
        tool["description"] = "This placeholder returns unconditional success for every requested Example operation."
        tool["implementation"]["symbol"] = "MissingSymbol"
        errors = "\n".join(self.errors(profile))
        self.assertIn("no-op marker 'placeholder'", errors)
        self.assertIn("'MissingSymbol' not found", errors)

    def test_revision_and_remote_auth_are_fail_closed(self) -> None:
        profile = copy.deepcopy(self.profile)
        profile["clients"][0]["evidence"][0]["revision"] = "d" * 40
        profile["protocol"]["remoteAuthorization"]["noTokenPassthrough"] = False
        errors = "\n".join(self.errors(profile))
        self.assertIn("must equal profile revision", errors)
        self.assertIn("noTokenPassthrough: must be true", errors)

    def test_wildcard_and_credential_bearing_origins_fail(self) -> None:
        profile = copy.deepcopy(self.profile)
        profile["integrations"][0]["allowedOrigins"] = [
            "https://operator:secret@*.github.com"
        ]
        errors = "\n".join(self.errors(profile))
        self.assertIn("wildcard or template origins are forbidden", errors)
        self.assertIn("credentials in origins are forbidden", errors)

    def test_credential_shaped_values_are_rejected(self) -> None:
        profile = copy.deepcopy(self.profile)
        credential_shape = "gh" + "p_" + ("1" * 30)
        profile["identity"]["summary"] += f" {credential_shape}"
        self.assertIn("profile: credential-shaped value is forbidden", self.errors(profile))

    def test_duplicate_json_keys_are_rejected(self) -> None:
        path = self.root / "duplicate.json"
        path.write_text('{"schemaVersion":1,"schemaVersion":1}', encoding="utf-8")
        with self.assertRaisesRegex(validator.DuplicateKeyError, "duplicate JSON key"):
            validator.load_json(path)

    def test_machine_readable_cli_result_is_stable(self) -> None:
        profile_path = self.root / "profile.json"
        profile_path.write_text(json.dumps(self.profile), encoding="utf-8")
        loaded = validator.load_json(profile_path)
        self.assertEqual(validator.validate_profile(loaded, self.root), [])


if __name__ == "__main__":
    unittest.main()
