import { createHash } from 'node:crypto';
import { readFile, realpath } from 'node:fs/promises';
import { isDeepStrictEqual } from 'node:util';
import { connectStdio } from './stdio.mjs';

const object = (value) => value !== null && typeof value === 'object' && !Array.isArray(value);
const demand = (condition, code) => { if (!condition) throw new Error(`MCP contract: ${code}`); };
const digest = (bytes) => createHash('sha256').update(bytes).digest('hex');

/** Always compile both independent lanes anew; never admit a caller-supplied status string. */
export async function admitContract(api, options) {
  const formatAssertion = options.formatAssertion === true;
  const report = await api.runCheck(options);
  demand(report.status === 'passed' && report.zeroUnexplainedFindings === true &&
    Array.isArray(report.findings) && report.findings.length === 0, 'parity did not pass');
  const sources = { typespec: options.typespec, authoredSchema: options.authoredSchema };
  const ir = await api.buildContractIr({ report, ...sources });
  async function verifyCurrent() {
    const verification = await api.verifyContractIr({ contractIr: ir, report, ...sources });
    demand(verification.schema === 'ores.typespec-json-schema-validator.contract-ir-verification/v1' &&
      verification.status === 'passed' && verification.admissible === true, 'IR evidence is not current');
  }
  await verifyCurrent();
  demand(Array.isArray(ir.declarations) && ir.declarations.length > 0, 'IR has no declarations');
  const [authored, generated] = await Promise.all([
    api.loadSchemaCollection(options.authoredSchema, { requireDialect: true }),
    api.loadSchemaCollection(report.inputs.generatedJsonSchema.input, { requireDialect: true }),
  ]);
  demand(authored.digest === report.inputs.authoredJsonSchema.digest &&
    generated.digest === report.inputs.generatedJsonSchema.digest, 'schema inputs changed during admission');
  const lanes = [api.buildLaneResolver(authored), api.buildLaneResolver(generated)];
  const declarations = new Map();
  for (const declaration of ir.declarations) {
    const name = declaration.names?.authoredJsonSchema;
    const a = authored.declarations.find((item) => item.name === name);
    const b = generated.declarations.find((item) => item.name === declaration.names?.generatedJsonSchema);
    demand(typeof name === 'string' && !declarations.has(name) && a && b, 'invalid IR declaration');
    declarations.set(name, [a, b]);
  }
  function pair(name) {
    demand(declarations.has(name), 'operation references an unadmitted declaration');
    return declarations.get(name);
  }
  function schema(name) { return structuredClone(pair(name)[0].schema); }
  return Object.freeze({
    runId: report.runId,
    irId: ir.irId,
    schema,
    verifyCurrent,
    accepts(name, instance) {
      const verdicts = pair(name).map((declaration, index) => {
        const result = api.validateInstance({ schema: declaration.schema, instance,
          resolver: lanes[index].resolver, base: lanes[index].baseFor(declaration), formatAssertion });
        demand(typeof result?.valid === 'boolean', 'validator did not return a verdict');
        return result.valid;
      });
      demand(verdicts[0] === verdicts[1], 'runtime payload diverged between authorities');
      return verdicts[0];
    },
    sameSchema(left, right) {
      return api.canonicalStringify(api.normalizeSchemaNodeForComparison(left)) ===
        api.canonicalStringify(api.normalizeSchemaNodeForComparison(right));
    },
  });
}

export function validateManifest(manifest) {
  demand(object(manifest) && manifest.schema === 'ores.mcp-tool-conformance/v1', 'unsupported operation manifest');
  demand(typeof manifest.protocolVersion === 'string' && /^\d{4}-\d{2}-\d{2}$/u.test(manifest.protocolVersion),
    'missing exact protocol version');
  demand(manifest.coverage === 'declared-tools-only', 'coverage must be explicit');
  demand(Array.isArray(manifest.tools) && manifest.tools.length > 0, 'empty tool inventory');
  const names = new Set();
  for (const tool of manifest.tools) {
    demand(object(tool) && typeof tool.name === 'string' && /^[A-Za-z0-9_.-]+$/u.test(tool.name) &&
      !names.has(tool.name), 'invalid or duplicate operation');
    names.add(tool.name);
    demand(typeof tool.input === 'string' && typeof tool.output === 'string', 'missing data declarations');
    demand(tool.encoding === 'json_text' || tool.encoding === 'structured', 'unsupported result encoding');
    demand(Array.isArray(tool.validArguments) && tool.validArguments.length > 0 &&
      Array.isArray(tool.invalidArguments) && tool.invalidArguments.length > 0, 'missing positive or negative calls');
    demand(tool.validArguments.every(object) && tool.invalidArguments.every(object), 'MCP arguments must be objects');
    demand(object(tool.expectedOutput), 'missing implementation identity expectations');
  }
}

export function assertCatalog(catalog, manifest, admitted) {
  demand(object(catalog) && Array.isArray(catalog.tools) && !catalog.nextCursor, 'incomplete tools catalog');
  const tools = new Map();
  for (const tool of catalog.tools) {
    demand(object(tool) && typeof tool.name === 'string' && !tools.has(tool.name), 'duplicate or invalid advertised tool');
    tools.set(tool.name, tool);
  }
  for (const operation of manifest.tools) {
    const tool = tools.get(operation.name);
    demand(tool && object(tool.inputSchema), 'declared tool absent from catalog');
    for (const value of [tool.inputSchema, tool.outputSchema].filter((item) => item !== undefined)) {
      demand(object(value) && (value.$schema === undefined ||
        value.$schema === 'https://json-schema.org/draft/2020-12/schema'), 'unsupported advertised dialect');
    }
    demand(admitted.sameSchema(tool.inputSchema, admitted.schema(operation.input)), 'advertised input schema drift');
    if (Object.hasOwn(tool, 'outputSchema')) {
      demand(admitted.sameSchema(tool.outputSchema, admitted.schema(operation.output)), 'advertised output schema drift');
    }
  }
}

export function readToolPayload(response, operation) {
  demand(!Object.hasOwn(response, 'error') && object(response.result) &&
    (response.result.isError === undefined || response.result.isError === false), 'valid call failed');
  const result = response.result;
  if (operation.encoding === 'structured') {
    demand(Object.hasOwn(result, 'structuredContent'), 'structured output missing');
    return result.structuredContent;
  }
  demand(Array.isArray(result.content) && result.content.length === 1 &&
    result.content[0]?.type === 'text' && typeof result.content[0].text === 'string', 'expected one JSON text result');
  let payload;
  try { payload = JSON.parse(result.content[0].text); } catch { throw new Error('MCP contract: malformed JSON text result'); }
  if (Object.hasOwn(result, 'structuredContent')) {
    // Reject disagreement rather than trusting one of two output representations.
    demand(isDeepStrictEqual(result.structuredContent, payload), 'conflicting output representations');
  }
  return payload;
}

export function assertInvalidCall(response) {
  demand((object(response.error) && response.error.code === -32602) ||
    (!Object.hasOwn(response, 'error') && object(response.result) && response.result.isError === true),
  'invalid arguments were not rejected by the implementation');
}

/** Test an actual executable after admission, then recheck source and binary identity. */
export async function checkImplementation({ binary, cwd, manifestPath, admitted, timeoutMs = 5000 }) {
  const executable = await realpath(binary);
  const binaryBefore = digest(await readFile(executable));
  const manifestBytes = await readFile(manifestPath);
  const manifest = JSON.parse(manifestBytes);
  validateManifest(manifest);
  // Recorded calls are evidence, not authority: validate their expected verdicts first.
  for (const operation of manifest.tools) {
    admitted.schema(operation.output);
    for (const args of operation.validArguments) demand(admitted.accepts(operation.input, args), 'positive call contradicts contract');
    for (const args of operation.invalidArguments) demand(!admitted.accepts(operation.input, args), 'negative call contradicts contract');
  }
  await admitted.verifyCurrent();
  const connection = connectStdio(executable, { cwd, timeoutMs });
  let validCalls = 0;
  let invalidCalls = 0;
  try {
    const initialized = await connection.request('initialize', { protocolVersion: manifest.protocolVersion,
      capabilities: {}, clientInfo: { name: 'ores-contract-conformance', version: '1.0.0' } });
    demand(initialized.result?.protocolVersion === manifest.protocolVersion, 'protocol negotiation drift');
    connection.notify('notifications/initialized');
    const catalog = await connection.request('tools/list');
    assertCatalog(catalog.result, manifest, admitted);
    for (const operation of manifest.tools) {
      for (const args of operation.validArguments) {
        const response = await connection.request('tools/call', { name: operation.name, arguments: args });
        const payload = readToolPayload(response, operation);
        demand(admitted.accepts(operation.output, payload), 'implementation output violates admitted contract');
        for (const [key, expected] of Object.entries(operation.expectedOutput)) {
          demand(object(payload) && Object.hasOwn(payload, key) && payload[key] === expected, 'implementation identity mismatch');
        }
        validCalls++;
      }
      for (const args of operation.invalidArguments) {
        assertInvalidCall(await connection.request('tools/call', { name: operation.name, arguments: args }));
        invalidCalls++;
      }
    }
    connection.assertHealthy();
    await admitted.verifyCurrent();
    demand(binaryBefore === digest(await readFile(executable)), 'executable changed during conformance');
    demand(digest(manifestBytes) === digest(await readFile(manifestPath)), 'operation manifest changed during conformance');
    connection.assertHealthy();
    return { schema: 'ores.mcp-tool-conformance-result/v1', status: 'passed',
      coverage: manifest.coverage, tools: manifest.tools.map((tool) => tool.name), validCalls, invalidCalls,
      parityRunId: admitted.runId, contractIrId: admitted.irId,
      binarySha256: binaryBefore, operationManifestSha256: digest(manifestBytes) };
  } finally { await connection.close(); }
}
