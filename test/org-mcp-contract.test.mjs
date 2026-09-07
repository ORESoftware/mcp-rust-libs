import assert from 'node:assert/strict';
import { test } from 'node:test';
import { chmod, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { isDeepStrictEqual } from 'node:util';
import { admitContract, assertCatalog, assertInvalidCall, checkImplementation, readToolPayload,
  validateManifest } from '../tooling/org-mcp-contract/index.mjs';
import { connectStdio } from '../tooling/org-mcp-contract/stdio.mjs';

const input = { type: 'object', additionalProperties: false };
const output = { type: 'object', properties: { organization: { type: 'string' } },
  required: ['organization'], additionalProperties: false };
function manifest() {
  return { schema: 'ores.mcp-tool-conformance/v1', protocolVersion: '2025-11-25',
    coverage: 'declared-tools-only', tools: [{ name: 'org_identity', input: 'NoArguments',
      output: 'OrgIdentity', encoding: 'json_text', validArguments: [{}],
      invalidArguments: [{ injected: true }], expectedOutput: { organization: 'example' } }] };
}
function admitted() {
  return { runId: 'a'.repeat(64), irId: 'b'.repeat(64), verifyCurrent: async () => {},
    schema(name) { assert.ok(['NoArguments', 'OrgIdentity'].includes(name)); return name === 'NoArguments' ? input : output; },
    sameSchema: isDeepStrictEqual,
    // Deliberate test double for runner control flow, not a production schema validator.
    accepts(name, value) {
      return name === 'NoArguments' ? isDeepStrictEqual(value, {}) :
        value !== null && typeof value === 'object' && Object.keys(value).length === 1 &&
        typeof value.organization === 'string';
    } };
}
const catalog = () => ({ tools: [{ name: 'org_identity', inputSchema: input }] });
const response = (value) => ({ result: { content: [{ type: 'text', text: JSON.stringify(value) }] } });

for (const [label, change] of [
  ['empty operations', (m) => { m.tools = []; }],
  ['duplicate operations', (m) => { m.tools.push(m.tools[0]); }],
  ['missing negative calls', (m) => { m.tools[0].invalidArguments = []; }],
  ['unsupported encoding', (m) => { m.tools[0].encoding = 'auto'; }],
  ['array arguments', (m) => { m.tools[0].validArguments = [[]]; }],
  ['implicit coverage', (m) => { delete m.coverage; }],
  ['unknown manifest version', (m) => { m.schema = 'future'; }],
]) test(`manifest rejects ${label}`, () => { const m = manifest(); change(m); assert.throws(() => validateManifest(m)); });
test('manifest accepts explicit bounded scope', () => validateManifest(manifest()));
for (const [label, change] of [
  ['missing tool', (c) => { c.tools = []; }],
  ['duplicate tools', (c) => { c.tools.push(c.tools[0]); }],
  ['input drift', (c) => { c.tools[0].inputSchema = { type: 'object' }; }],
  ['output drift', (c) => { c.tools[0].outputSchema = { type: 'string' }; }],
  ['incomplete pagination', (c) => { c.nextCursor = 'next'; }],
  ['unsupported dialect', (c) => { c.tools[0].inputSchema = { ...input, $schema: 'draft-07' }; }],
]) test(`catalog rejects ${label}`, () => { const c = catalog(); change(c); assert.throws(() => assertCatalog(c, manifest(), admitted())); });
test('catalog accepts explicit json-text compatibility contract', () => assertCatalog(catalog(), manifest(), admitted()));
test('negative call rejects success and unrelated internal errors', () => {
  assert.throws(() => assertInvalidCall(response({}))); assert.throws(() => assertInvalidCall({ error: { code: -32603 } }));
  assertInvalidCall({ error: { code: -32602 } }); assertInvalidCall({ result: { isError: true } });
});
test('malformed tool text is redacted from diagnostics', () => {
  assert.throws(() => readToolPayload({ result: { content: [{ type: 'text', text: 'SECRET_SENTINEL' }] } }, manifest().tools[0]),
    (error) => !error.message.includes('SECRET_SENTINEL') && error.message.includes('malformed'));
});
test('structured results require presence, not truthiness', () => {
  const op = { encoding: 'structured' }; assert.equal(readToolPayload({ result: { structuredContent: false } }, op), false);
  assert.throws(() => readToolPayload({ result: {} }, op));
});
test('dual output encodings must agree independent of object order', () => {
  const r = response({ a: 1, b: 2 }); r.result.structuredContent = { b: 2, a: 1 };
  assert.deepEqual(readToolPayload(r, manifest().tools[0]), { a: 1, b: 2 });
  r.result.structuredContent.a = 9; assert.throws(() => readToolPayload(r, manifest().tools[0]));
});
test('parity status strings do not bypass IR verification', async () => {
  const api = { runCheck: async () => ({ status: 'passed', zeroUnexplainedFindings: true, findings: [] }),
    buildContractIr: async () => ({}), verifyContractIr: async () => ({ status: 'passed' }) };
  await assert.rejects(admitContract(api, {}), /IR evidence/);
});
test('failed parity never constructs IR', async () => {
  await assert.rejects(admitContract({ runCheck: async () => ({ status: 'failed' }),
    buildContractIr: async () => assert.fail('must not build IR') }, {}), /parity did not pass/);
});

const server = `import { createInterface } from 'node:readline';
const mode = MODE;
createInterface({input:process.stdin}).on('line', line => {
 const m=JSON.parse(line); if (!Object.hasOwn(m,'id')) return;
 if(mode==='timeout')return;
 if(mode==='stderr'){process.stderr.write('x'.repeat(4096));return;}
 if(mode==='garbage'){console.log('SECRET_SENTINEL');return;}
 if(mode==='exit'){process.exit(0);}
 let result;
 if(m.method==='initialize') result={protocolVersion:mode==='protocol'?'2024-11-05':m.params.protocolVersion};
 else if(m.method==='tools/list')result={tools:[{name:'org_identity',inputSchema:{type:'object',additionalProperties:false}}]};
 else if(Object.keys(m.params.arguments).length&&mode!=='accept-invalid'){
   console.log(JSON.stringify({jsonrpc:'2.0',id:m.id,error:{code:-32602,message:'invalid arguments'}}));return;
 }else result={content:[{type:'text',text:JSON.stringify({organization:mode==='identity'?'wrong':'example',
   ...(mode==='output'?{secret:'DO_NOT_PRINT'}:{})})}]};
 console.log(JSON.stringify({jsonrpc:'2.0',id:mode==='wrong-id'?999:m.id,result}));
});`;
async function fake(t, mode = 'ok') {
  const directory = await mkdtemp(join(tmpdir(), 'mcp-contract-test-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const binary = join(directory, 'server');
  await writeFile(binary, `#!${process.execPath}\n${server.replace('MODE', JSON.stringify(mode))}`);
  await chmod(binary, 0o700);
  const manifestPath = join(directory, 'operations.json');
  await writeFile(manifestPath, JSON.stringify(manifest()));
  return { binary, cwd: directory, manifestPath, admitted: admitted() };
}
test('real stdio exchange produces binary/operation-bound evidence', async (t) => {
  const result = await checkImplementation(await fake(t));
  assert.equal(result.status, 'passed'); assert.equal(result.validCalls, 1); assert.equal(result.invalidCalls, 1);
  assert.match(result.binarySha256, /^[a-f0-9]{64}$/); assert.match(result.operationManifestSha256, /^[a-f0-9]{64}$/);
  assert.deepEqual(result.tools, ['org_identity']);
});
for (const mode of ['protocol', 'identity', 'output', 'accept-invalid', 'garbage', 'wrong-id', 'exit']) {
  test(`real stdio runner rejects ${mode}`, async (t) => {
    await assert.rejects(checkImplementation(await fake(t, mode)), (error) =>
      !error.message.includes('SECRET_SENTINEL') && !error.message.includes('DO_NOT_PRINT'));
  });
}
test('timeouts terminate server and reject pending calls', async (t) => {
  const f = await fake(t, 'timeout');
  await assert.rejects(checkImplementation({ ...f, timeoutMs: 300 }), /timed out/);
});
test('stderr is bounded without exposing its contents', async (t) => {
  const f = await fake(t, 'stderr'); const client = connectStdio(f.binary, { maxBytes: 1024 });
  try { await assert.rejects(client.request('initialize'), /exceeded bound/); } finally { await client.close(); }
});
test('post-run input drift prevents passed evidence', async (t) => {
  const f = await fake(t); let calls = 0;
  f.admitted.verifyCurrent = async () => { if (++calls === 2) throw new Error('stale input evidence'); };
  await assert.rejects(checkImplementation(f), /stale input/);
});
test('operation manifest edits during a run invalidate evidence', async (t) => {
  const f = await fake(t); let calls = 0;
  f.admitted.verifyCurrent = async () => { if (++calls === 2) await writeFile(f.manifestPath, `${await readFile(f.manifestPath)} `); };
  await assert.rejects(checkImplementation(f), /manifest changed/);
});
test('relative executables are refused', () => assert.throws(() => connectStdio('server'), /configuration/));

function authorityApi() {
  const calls = [];
  const a = { name: 'NoArguments', source: 'a.json', schema: { ...input } };
  const b = { name: 'NoArguments', source: 'b.json', schema: { ...input } };
  const report = { status: 'passed', zeroUnexplainedFindings: true, findings: [], runId: 'a'.repeat(64),
    inputs: { authoredJsonSchema: { digest: 'authored' }, generatedJsonSchema: { input: 'generated', digest: 'generated' } } };
  const api = {
    runCheck: async () => report,
    buildContractIr: async () => ({ irId: 'b'.repeat(64), declarations: [{
      names: { authoredJsonSchema: 'NoArguments', generatedJsonSchema: 'NoArguments' },
      assertionSchema: { $ref: 'urn:comparison-only:must-not-execute' } }] }),
    verifyContractIr: async () => ({ schema: 'ores.typespec-json-schema-validator.contract-ir-verification/v1',
      status: 'passed', admissible: true }),
    loadSchemaCollection: async (lane) => ({ digest: lane, declarations: [lane === 'authored' ? a : b] }),
    buildLaneResolver: (collection) => ({ resolver: collection.digest, baseFor: (declaration) => declaration.source }),
    validateInstance: (options) => { calls.push(options); return { valid: true }; },
  };
  return { api, calls };
}
test('admission executes original lane schemas and resolvers, never comparison IR', async () => {
  const { api, calls } = authorityApi();
  const contract = await admitContract(api, { typespec: 'main.tsp', authoredSchema: 'authored', formatAssertion: true });
  assert.equal(contract.accepts('NoArguments', {}), true);
  assert.deepEqual(calls.map((call) => [call.resolver, call.base, call.formatAssertion]),
    [['authored', 'a.json', true], ['generated', 'b.json', true]]);
  assert.ok(calls.every((call) => call.schema.$ref === undefined));
  const projection = contract.schema('NoArguments'); projection.additionalProperties = true;
  assert.equal(contract.schema('NoArguments').additionalProperties, false);
  assert.throws(() => contract.schema('Unadmitted'));
});
test('payload disagreement between actual schema lanes stops conformance', async () => {
  const { api } = authorityApi(); api.validateInstance = ({ resolver }) => ({ valid: resolver === 'authored' });
  const contract = await admitContract(api, { authoredSchema: 'authored' });
  assert.throws(() => contract.accepts('NoArguments', {}), /diverged/);
});
test('unsupported validation is not counted as an invalid payload', async () => {
  const { api } = authorityApi(); api.validateInstance = () => { throw new Error('unsupported schema'); };
  const contract = await admitContract(api, { authoredSchema: 'authored' });
  assert.throws(() => contract.accepts('NoArguments', {}), /unsupported/);
});
test('source changes between receipt verification and schema loading stop admission', async () => {
  const { api } = authorityApi(); api.loadSchemaCollection = async () => ({ digest: 'changed' });
  await assert.rejects(admitContract(api, { authoredSchema: 'authored' }), /inputs changed/);
});
