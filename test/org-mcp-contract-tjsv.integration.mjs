import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { copyFile, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { promisify } from 'node:util';
import test from 'node:test';

import { admitContract } from '../tooling/org-mcp-contract/index.mjs';

const execFileAsync = promisify(execFile);
const packageRoot = resolve(import.meta.dirname, '..');
const pin = JSON.parse(await readFile(join(packageRoot, 'tooling/org-mcp-contract/tjsv.lock.json'), 'utf8'));
const tjsvRoot = process.env.TJSV_ROOT ? resolve(process.env.TJSV_ROOT) : null;
const requireReal = process.env.REQUIRE_TJSV_REAL === '1';
const realTest = tjsvRoot ? test : test.skip;

async function importPinned(relativePath) {
  assert.ok(tjsvRoot, 'TJSV_ROOT is required for real-validator integration');
  return import(pathToFileURL(join(tjsvRoot, relativePath)).href);
}

async function fixturePaths() {
  assert.ok(tjsvRoot);
  return {
    typespec: join(tjsvRoot, 'test/fixtures/pass/main.tsp'),
    authoredSchema: join(tjsvRoot, 'test/fixtures/pass/authored.schema.json'),
  };
}

async function admittedFixture(t, { authoredSchema } = {}) {
  const directory = await mkdtemp(join(tmpdir(), 'mcp-tjsv-real-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const api = await importPinned(pin.entrypoint);
  const fixtures = await fixturePaths();
  const source = authoredSchema ?? fixtures.authoredSchema;
  const admitted = await admitContract(api, {
    typespec: fixtures.typespec,
    authoredSchema: source,
    outputDir: join(directory, 'generated'),
    maxFindings: 250,
    maxProbes: 64,
  });
  return { api, admitted, directory, ...fixtures, authoredSchema: source };
}

test('dedicated CI cannot silently skip the real TJSV gate', () => {
  if (requireReal) assert.ok(tjsvRoot, 'REQUIRE_TJSV_REAL requires TJSV_ROOT');
});

test('the repository records an immutable peer-authority TJSV pin', () => {
  assert.equal(pin.schema, 'ores.mcp-tjsv-pin/v1');
  assert.equal(pin.repository, 'ORESoftware/typespec-json-schema-validator');
  assert.match(pin.revision, /^[a-f0-9]{40}$/u);
  assert.equal(pin.typeSpecAuthority, 'peer');
  assert.equal(pin.jsonSchemaAuthority, 'peer');
  assert.equal(pin.generatedWitnessRole, 'evidence_only');
});

realTest('checked-out TJSV source exactly matches the reviewed immutable pin', async () => {
  const { stdout } = await execFileAsync('git', ['rev-parse', 'HEAD'], { cwd: tjsvRoot, encoding: 'utf8' });
  assert.equal(stdout.trim(), pin.revision);
  const packageJson = JSON.parse(await readFile(join(tjsvRoot, 'package.json'), 'utf8'));
  assert.equal(packageJson.name, '@oresoftware/typespec-json-schema-validator');
});

realTest('pinned TJSV exposes every API used by MCP contract admission', async () => {
  const api = await importPinned(pin.entrypoint);
  for (const name of [
    'runCheck', 'buildContractIr', 'verifyContractIr', 'loadSchemaCollection',
    'buildLaneResolver', 'validateInstance', 'normalizeSchemaNodeForComparison', 'canonicalStringify',
  ]) assert.equal(typeof api[name], 'function', `missing pinned TJSV API: ${name}`);
});

realTest('real compiler-backed TJSV admission produces current SHA-256 evidence', async (t) => {
  const { admitted } = await admittedFixture(t);
  assert.match(admitted.runId, /^[a-f0-9]{64}$/u);
  assert.match(admitted.irId, /^[a-f0-9]{64}$/u);
  await admitted.verifyCurrent();
});

realTest('both admitted schema lanes accept the same valid runtime payload', async (t) => {
  const { admitted } = await admittedFixture(t);
  assert.equal(admitted.accepts('User', { id: 'u-1', role: 'admin', active: true }), true);
  assert.equal(admitted.accepts('User', {
    id: 'u-2', role: 'member', active: false, displayName: 'Ada',
  }), true);
});

realTest('both admitted schema lanes reject missing required runtime data', async (t) => {
  const { admitted } = await admittedFixture(t);
  assert.equal(admitted.accepts('User', { id: 'u-1', role: 'admin' }), false);
});

realTest('both admitted schema lanes reject unknown enum values', async (t) => {
  const { admitted } = await admittedFixture(t);
  assert.equal(admitted.accepts('User', { id: 'u-1', role: 'owner', active: true }), false);
});

realTest('both admitted schema lanes reject undeclared fields', async (t) => {
  const { admitted } = await admittedFixture(t);
  assert.equal(admitted.accepts('User', {
    id: 'u-1', role: 'member', active: true, isAdmin: true,
  }), false);
});

realTest('TJSV compilation never rewrites either authored authority', async (t) => {
  const { typespec, authoredSchema } = await fixturePaths();
  const [typespecBefore, schemaBefore] = await Promise.all([
    readFile(typespec), readFile(authoredSchema),
  ]);
  await admittedFixture(t);
  const [typespecAfter, schemaAfter] = await Promise.all([
    readFile(typespec), readFile(authoredSchema),
  ]);
  assert.deepEqual(typespecAfter, typespecBefore);
  assert.deepEqual(schemaAfter, schemaBefore);
});

realTest('a disagreement between authored JSON Schema and TypeSpec fails closed', async (t) => {
  const directory = await mkdtemp(join(tmpdir(), 'mcp-tjsv-diverge-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const fixtures = await fixturePaths();
  const authoredSchema = join(directory, 'authored.schema.json');
  await copyFile(fixtures.authoredSchema, authoredSchema);
  const document = JSON.parse(await readFile(authoredSchema, 'utf8'));
  document.$defs.Role.enum = ['member'];
  await writeFile(authoredSchema, `${JSON.stringify(document, null, 2)}\n`, 'utf8');
  const api = await importPinned(pin.entrypoint);
  await assert.rejects(admitContract(api, {
    typespec: fixtures.typespec,
    authoredSchema,
    outputDir: join(directory, 'generated'),
    maxFindings: 250,
    maxProbes: 64,
  }));
});

realTest('post-admission source drift invalidates the retained Contract IR evidence', async (t) => {
  const directory = await mkdtemp(join(tmpdir(), 'mcp-tjsv-stale-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const fixtures = await fixturePaths();
  const authoredSchema = join(directory, 'authored.schema.json');
  await copyFile(fixtures.authoredSchema, authoredSchema);
  const { admitted } = await admittedFixture(t, { authoredSchema });
  const document = JSON.parse(await readFile(authoredSchema, 'utf8'));
  document.$defs.User.properties.displayName.maxLength = 120;
  await writeFile(authoredSchema, `${JSON.stringify(document, null, 2)}\n`, 'utf8');
  await assert.rejects(admitted.verifyCurrent());
});

realTest('pinned TJSV language-boundary promotion gate is callable and fail-closed', async () => {
  const boundary = await importPinned(pin.languageBoundaryEntrypoint);
  assert.equal(typeof boundary.verifyLanguageBoundaries, 'function');
  const result = boundary.verifyLanguageBoundaries({});
  assert.equal(result.status, 'stopped_for_evaluation');
  assert.equal(result.zeroUnexplainedFindings, false);
  assert.equal(result.binding.typeSpecAuthority, 'peer');
  assert.equal(result.binding.jsonSchemaAuthority, 'peer');
  assert.equal(result.binding.generatedWitnessRole, 'evidence_only');
  assert.ok(result.findings.length > 0);
});
