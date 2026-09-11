import assert from 'node:assert/strict';
import { test } from 'node:test';

import { assertCatalog, validateManifest } from '../tooling/org-mcp-contract/index.mjs';

const emptyInput = { type: 'object', additionalProperties: false };

function operation(name = 'org_identity', surface = 'regular') {
  return {
    name,
    surface,
    input: 'NoArguments',
    output: 'OrgIdentity',
    encoding: 'json_text',
    validArguments: [{}],
    invalidArguments: [{ injected: true }],
    expectedOutput: { organization: 'example' },
  };
}

function exactManifest(serverClass = 'regular', tools = [operation()]) {
  return {
    schema: 'ores.mcp-tool-conformance/v1',
    protocolVersion: '2025-11-25',
    coverage: 'exact-tools',
    serverClass,
    tools,
  };
}

const admitted = {
  schema: () => emptyInput,
  sameSchema: (left, right) => JSON.stringify(left) === JSON.stringify(right),
};

function catalog(...names) {
  return { tools: names.map((name) => ({ name, inputSchema: emptyInput })) };
}

test('regular exact manifest accepts only regular-surface tools', () => {
  validateManifest(exactManifest());
});

test('regular exact manifest cannot declare an admin-surface tool', () => {
  const value = exactManifest('regular', [operation('org_identity'), operation('rotate_credentials', 'admin')]);
  assert.throws(() => validateManifest(value), /regular server cannot declare admin-surface tools/);
});

test('admin exact manifest may explicitly declare regular and admin surfaces', () => {
  validateManifest(exactManifest('admin', [operation('org_identity'), operation('rotate_credentials', 'admin')]));
});

test('exact catalog requires an explicit deployable server class', () => {
  const value = exactManifest();
  delete value.serverClass;
  assert.throws(() => validateManifest(value), /serverClass/);
});

test('exact catalog requires every tool to declare its reviewed surface', () => {
  const value = exactManifest();
  delete value.tools[0].surface;
  assert.throws(() => validateManifest(value), /tool surface/);
});

test('regular exact catalog rejects an undeclared extra tool even when declared tools are present', () => {
  const value = exactManifest();
  validateManifest(value);
  assert.throws(
    () => assertCatalog(catalog('org_identity', 'admin_rotate_credentials'), value, admitted),
    /unexpected tool in exact catalog/,
  );
});

test('regular exact catalog accepts the complete reviewed set and no extras', () => {
  const value = exactManifest();
  validateManifest(value);
  assertCatalog(catalog('org_identity'), value, admitted);
});

test('legacy declared-tools-only coverage remains explicitly partial and backward compatible', () => {
  const value = exactManifest();
  value.coverage = 'declared-tools-only';
  delete value.serverClass;
  delete value.tools[0].surface;
  validateManifest(value);
  assertCatalog(catalog('org_identity', 'unreviewed_extra_tool'), value, admitted);
});
