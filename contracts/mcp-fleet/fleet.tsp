import "@typespec/http";

using TypeSpec.Http;

namespace Ores.McpFleet;

@doc("Classification is review metadata only; authorization is enforced outside this value.")
enum ServerClass {
  regular,
  admin,
}

model Authorities {
  interfaces: "ORESoftware/ores-interfaces";
  apiDocs: "ORESoftware/api-docs";
  schemaValidator: "ORESoftware/typespec-json-schema-validator";
  sharedRuntime: "ORESoftware/mcp-rust-libs";
  telemetryCore: "ores-otel/ores-mcp-server-core-libs.rs";
  ecosystemPrefix: "ORESoftware/ores-";
}

model SecurityContract {
  closedToolSchemas: true;
  boundedOutputs: true;
  secretToolArguments: false;
  adminSeparateDeployable: true;
  clientRoleGrantsAdmin: false;
  genericExecutionAllowed: false;
}

model ContractAuthorities {
  jsonSchemaDraft: "2020-12";
  apiDocsSchema: "ore.api-docs.v1";
  typeSpecAuthority: "independent";
  jsonSchemaAuthority: "independent";
  failClosedEvidence: true;
}

model AdminContract {
  mutationsDelegateToAdminApi: true;
  auditReasonRequired: boolean;
  stepUpRequired: boolean;
  crossTenantByDefault: false;
}

model FleetManifest {
  schemaVersion: "ores.mcp-fleet.v1";
  serverClass: ServerClass;
  authorities: Authorities;
  security: SecurityContract;
  contracts: ContractAuthorities;
  admin?: AdminContract;
}
