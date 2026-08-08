#!/usr/bin/env python3
from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import tempfile
import unittest
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "tooling" / "validate_api_docs_contract.py"
SPEC = importlib.util.spec_from_file_location("validate_api_docs_contract", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
validator = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = validator
SPEC.loader.exec_module(validator)

MANIFEST_PATH = ROOT / "contracts" / "api-docs" / "example.manifest.json"
OPENAPI_PATH = ROOT / "contracts" / "api-docs" / "example.openapi.json"


class ApiDocsContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.openapi_bytes = OPENAPI_PATH.read_bytes()
        self.openapi = json.loads(self.openapi_bytes)
        self.manifest = json.loads(MANIFEST_PATH.read_bytes())

    def validate(self, manifest=None, openapi=None, openapi_bytes=None):
        return validator.validate_contract(
            self.manifest if manifest is None else manifest,
            self.openapi if openapi is None else openapi,
            self.openapi_bytes if openapi_bytes is None else openapi_bytes,
            expected_mcp_repository="example/example-mcp-server.rs",
        )

    def test_example_contract_is_valid_and_deterministic(self) -> None:
        summary, operations = self.validate()
        self.assertEqual(summary.service, "example-api-server")
        self.assertEqual(summary.openapi_version, "3.1.0")
        self.assertEqual(summary.operation_count, 3)
        self.assertEqual(summary.read_only_operation_count, 2)
        self.assertEqual(
            summary.openapi_sha256,
            hashlib.sha256(self.openapi_bytes).hexdigest(),
        )
        self.assertEqual(
            [operation.operation_id for operation in operations],
            ["createWidget", "getHealth", "listWidgets"],
        )

    def test_hash_mismatch_fails_closed(self) -> None:
        manifest = copy.deepcopy(self.manifest)
        manifest["public"]["openapi"]["sha256"] = "0" * 64
        with self.assertRaisesRegex(
            validator.ContractError, "does not match the exact OpenAPI response bytes"
        ):
            self.validate(manifest=manifest)

    def test_noncanonical_route_is_rejected(self) -> None:
        manifest = copy.deepcopy(self.manifest)
        manifest["public"]["openapi"]["path"] = "/swagger.json"
        with self.assertRaisesRegex(
            validator.ContractError, "must equal /openapi.json"
        ):
            self.validate(manifest=manifest)

    def test_absolute_or_network_path_is_rejected(self) -> None:
        manifest = copy.deepcopy(self.manifest)
        manifest["public"]["ui"]["aliases"] = ["//attacker.example/docs", "/docs/api"]
        with self.assertRaisesRegex(
            validator.ContractError, "root-relative HTTP path"
        ):
            self.validate(manifest=manifest)

    def test_mcp_pair_must_be_in_same_organization(self) -> None:
        manifest = copy.deepcopy(self.manifest)
        manifest["mcp"]["repository"] = "other/example-mcp-server.rs"
        with self.assertRaisesRegex(
            validator.ContractError, "same GitHub organization"
        ):
            validator.validate_contract(
                manifest, self.openapi, self.openapi_bytes
            )

    def test_required_read_only_tools_cannot_drift(self) -> None:
        manifest = copy.deepcopy(self.manifest)
        manifest["mcp"]["tools"].remove("api_docs_describe_operation")
        with self.assertRaisesRegex(
            validator.ContractError, "missing required read-only API-doc tools"
        ):
            self.validate(manifest=manifest)

    def test_duplicate_operation_ids_are_rejected(self) -> None:
        openapi = copy.deepcopy(self.openapi)
        openapi["paths"]["/v1/widgets"]["get"]["operationId"] = "getHealth"
        openapi_bytes = (json.dumps(openapi, indent=2, sort_keys=True) + "\n").encode()
        manifest = copy.deepcopy(self.manifest)
        manifest["public"]["openapi"]["sha256"] = hashlib.sha256(openapi_bytes).hexdigest()
        with self.assertRaisesRegex(
            validator.ContractError, "is not unique"
        ):
            self.validate(
                manifest=manifest,
                openapi=openapi,
                openapi_bytes=openapi_bytes,
            )

    def test_internal_operation_cannot_leak_into_public_document(self) -> None:
        openapi = copy.deepcopy(self.openapi)
        openapi["paths"]["/healthz"]["get"]["x-ore-visibility"] = "internal"
        openapi_bytes = (json.dumps(openapi, indent=2, sort_keys=True) + "\n").encode()
        manifest = copy.deepcopy(self.manifest)
        manifest["public"]["openapi"]["sha256"] = hashlib.sha256(openapi_bytes).hexdigest()
        with self.assertRaisesRegex(
            validator.ContractError, "contains internal operation"
        ):
            self.validate(
                manifest=manifest,
                openapi=openapi,
                openapi_bytes=openapi_bytes,
            )

    def test_unsafe_operation_cannot_claim_read_only(self) -> None:
        openapi = copy.deepcopy(self.openapi)
        operation = openapi["paths"]["/v1/widgets"]["post"]
        operation["x-ore-mcp-mutating"] = False
        openapi_bytes = (json.dumps(openapi, indent=2, sort_keys=True) + "\n").encode()
        manifest = copy.deepcopy(self.manifest)
        manifest["public"]["openapi"]["sha256"] = hashlib.sha256(openapi_bytes).hexdigest()
        with self.assertRaisesRegex(
            validator.ContractError, "must be marked mutating"
        ):
            self.validate(
                manifest=manifest,
                openapi=openapi,
                openapi_bytes=openapi_bytes,
            )

    def test_mutation_is_not_baseline_mcp_exposed(self) -> None:
        openapi = copy.deepcopy(self.openapi)
        operation = openapi["paths"]["/v1/widgets"]["post"]
        operation["x-ore-mcp-expose"] = True
        openapi_bytes = (json.dumps(openapi, indent=2, sort_keys=True) + "\n").encode()
        manifest = copy.deepcopy(self.manifest)
        manifest["public"]["openapi"]["sha256"] = hashlib.sha256(openapi_bytes).hexdigest()
        with self.assertRaisesRegex(
            validator.ContractError, "cannot be exposed"
        ):
            self.validate(
                manifest=manifest,
                openapi=openapi,
                openapi_bytes=openapi_bytes,
            )

    def test_cli_emits_machine_readable_summary(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "output.json"
            # Exercise main without a subprocess so the test remains portable.
            from contextlib import redirect_stdout
            with output.open("w", encoding="utf-8") as stream, redirect_stdout(stream):
                status = validator.main(
                    [
                        "--manifest",
                        str(MANIFEST_PATH),
                        "--openapi",
                        str(OPENAPI_PATH),
                        "--expected-mcp-repository",
                        "example/example-mcp-server.rs",
                        "--operations",
                    ]
                )
            self.assertEqual(status, 0)
            result = json.loads(output.read_text())
            self.assertEqual(result["operationCount"], 3)
            self.assertEqual(result["discoveryPath"], "/.well-known/api-docs")
            self.assertEqual(len(result["operations"]), 3)


if __name__ == "__main__":
    unittest.main()
