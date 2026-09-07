import assert from 'node:assert/strict';
import { test } from 'node:test';
import { parseStrictJson, STRICT_JSON_POLICY } from '../tooling/org-mcp-contract/json.mjs';
import { connectStdio } from '../tooling/org-mcp-contract/stdio.mjs';

const redacted = (error) => error instanceof Error && error.message.startsWith('MCP contract:') &&
  !error.message.includes('SECRET_SENTINEL');
const line = (body) => Buffer.from(body + '\n');
const response = (result) => `{"jsonrpc":"2.0","id":1,"result":${result}}`;
const deep = (depth) => '['.repeat(depth) + 'null' + ']'.repeat(depth);

test('wire policy identity is versioned', () => assert.equal(STRICT_JSON_POLICY, 'ores.mcp-strict-json/v1'));
for (const text of ['null', 'false', 'true', '0', '-0', '-1.25e+2', '1e-300', '[]', '{}',
  ' { "a" : [1, false, null, "x"], "nested": {"a":2} }\n',
  '"escaped \\\" quote and \\\\ backslash"', '"\\ud83d\\ude00"', '"你好🙂"',
  '{"__proto__":{"polluted":true},"constructor":3,"prototype":4}',
  '{"required":["b","a"],"title":"literal","oneOf":[1,1]}',
  '{"é":1,"é":2}', '[{"a":1},{"a":2}]', deep(64)]) {
  test(`preserves a valid JSON value ${text.slice(0, 45)}`, () => {
    assert.deepEqual(parseStrictJson(text), JSON.parse(text));
    assert.deepEqual(parseStrictJson(Buffer.from(text)), JSON.parse(text));
  });
}
for (const [name, text] of [
  ['top-level duplicate', '{"role":"SECRET_SENTINEL","role":"expected"}'],
  ['escaped duplicate', '{"name":1,"na\\u006de":2}'],
  ['nested duplicate', '{"ok":[{"x":1,"x":1}]}'],
  ['prototype duplicate', '{"__proto__":1,"__proto__":2}'],
  ['empty-name duplicate', '{"":1,"":2}'],
  ['surrogate-pair duplicate', '{"😀":1,"\\ud83d\\ude00":2}'],
  ['overflow', '1e999'], ['negative overflow', '-1e999'],
  ['depth', deep(65)], ['lone escaped surrogate', '"\\ud800"'],
  ['lone literal surrogate', '"\udc00"'], ['BOM', '\ufeff{}'],
  ['empty input', ''], ['invalid whitespace', '\u00a0{}'], ['trailing material', '{}{}'],
  ['trailing object comma', '{"x":1,}'], ['trailing array comma', '[1,]'],
  ['missing value', '{"x":}'], ['missing colon', '{"x" 1}'], ['leading zero', '01'],
  ['invalid exponent', '1e'], ['leading plus', '+1'], ['hexadecimal', '0x01'],
  ['bare NaN', 'NaN'], ['bad escape', '"\\x41"'], ['unescaped newline', '"x\ny"'],
  ['unterminated string', '"SECRET_SENTINEL'], ['unterminated container', '{"x":1'],
]) test(`rejects ${name} with payload-free diagnostics`, () => assert.throws(() => parseStrictJson(text), redacted));
for (const bytes of [[0xff], [0xc0, 0xaf], [0xed, 0xa0, 0x80], [0xf4, 0x90, 0x80, 0x80], [0xe2, 0x82]]) {
  test(`rejects invalid UTF-8 bytes ${bytes.join('-')}`, () => {
    const raw = Buffer.concat([Buffer.from('"'), Buffer.from(bytes), Buffer.from('"')]);
    assert.throws(() => parseStrictJson(raw), redacted);
  });
}
test('byte and depth boundaries are exact and cannot be disabled', () => {
  assert.equal(parseStrictJson('"é"', { maxBytes: 4 }), 'é');
  assert.throws(() => parseStrictJson('"é"', { maxBytes: 3 }), redacted);
  assert.deepEqual(parseStrictJson('[{}]', { maxDepth: 2 }), [{}]);
  assert.throws(() => parseStrictJson('[{}]', { maxDepth: 1 }), redacted);
  for (const options of [{ maxBytes: 0 }, { maxBytes: Infinity }, { maxBytes: 1048577 },
    { maxDepth: 0 }, { maxDepth: 65 }, { maxDepth: 1.5 }]) {
    assert.throws(() => parseStrictJson('{}', options), redacted);
  }
  assert.throws(() => parseStrictJson({}), redacted);
});
test('prototype-shaped members remain data and do not mutate prototypes', () => {
  const value = parseStrictJson('{"__proto__":{"polluted":true}}');
  assert.ok(Object.hasOwn(value, '__proto__'));
  assert.equal(Object.getPrototypeOf(value), Object.prototype);
  assert.equal({}.polluted, undefined);
});
test('a large malformed integer fails without echoing bytes', () => {
  assert.throws(() => parseStrictJson('9'.repeat(1048576)), redacted);
  assert.throws(() => parseStrictJson(' '.repeat(1048577)), redacted);
});

function childFor(bytes, suffix = '') {
  return connectStdio(process.execPath, { timeoutMs: 2000, args: ['-e',
    `process.stdin.once('data',()=>{process.stdout.write(Buffer.from('${bytes.toString('base64')}','base64'));${suffix}});`] });
}
const badFrames = [
  ['duplicate result member', line(response('{"role":"SECRET_SENTINEL","role":"expected"}'))],
  ['duplicate RPC id', line('{"jsonrpc":"2.0","id":99,"id":1,"result":{}}')],
  ['invalid UTF8 response', Buffer.concat([Buffer.from(response('"').slice(0,-1)), Buffer.from([255]), Buffer.from('"}\n')])],
  ['deep response', line(response(deep(65)))],
  ['nonfinite response', line(response('1e999'))],
  ['notification with result', line('{"jsonrpc":"2.0","method":"event","result":{}}\n' + response('{}'))],
  ['notification with error', line('{"jsonrpc":"2.0","method":"event","error":{"code":1,"message":"x"}}\n' + response('{}'))],
  ['notification scalar params', line('{"jsonrpc":"2.0","method":"event","params":false}\n' + response('{}'))],
  ['notification absent method', line('{"jsonrpc":"2.0","params":{}}\n' + response('{}'))],
];
for (const [label, bytes] of badFrames) test(`real stdio rejects ${label}`, async () => {
  const rpc = childFor(bytes);
  try { await assert.rejects(rpc.request('initialize'), redacted); }
  finally { await rpc.close(); }
});
test('strict decoding permits UTF8 split across multiple stream chunks', async () => {
  const bytes = line(response('"é🙂"'));
  const splits = [...bytes].map((b) => Buffer.from([b]).toString('base64'));
  const rpc = connectStdio(process.execPath, { timeoutMs: 3000, args: ['-e',
    `process.stdin.once('data',async()=>{for(const b of ${JSON.stringify(splits)}){process.stdout.write(Buffer.from(b,'base64'));await new Promise(r=>setTimeout(r,1));}});`] });
  try { assert.equal((await rpc.request('initialize')).result, 'é🙂'); }
  finally { await rpc.close(); }
  rpc.assertHealthy();
});
test('valid notifications may precede a response without becoming response evidence', async () => {
  const rpc = childFor(line('{"jsonrpc":"2.0","method":"notifications/progress","params":{"n":1}}\n' + response('{}')));
  try { assert.deepEqual((await rpc.request('initialize')).result, {}); rpc.assertHealthy(); }
  finally { await rpc.close(); }
});
test('an unterminated tail is reported when the child is drained', async () => {
  const rpc = childFor(Buffer.from(response('{}') + '\n{"secret":"SECRET_SENTINEL"'));
  try { await rpc.request('initialize'); } finally { await rpc.close(); }
  assert.throws(() => rpc.assertHealthy(), redacted);
});
test('clean shutdown remains healthy', async () => {
  const rpc = childFor(line(response('{}')));
  try { await rpc.request('initialize'); } finally { await rpc.close(); }
  rpc.assertHealthy();
});

// These are runner tests; the authority below is explicitly a test double.
import { chmod, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { readToolPayload, checkImplementation } from '../tooling/org-mcp-contract/index.mjs';
const input = { type: 'object', additionalProperties: false };
const manifest = { schema: 'ores.mcp-tool-conformance/v1', protocolVersion: '2025-11-25',
  coverage: 'declared-tools-only', tools: [{ name: 'identity', input: 'Input', output: 'Output',
    encoding: 'json_text', validArguments: [{}], invalidArguments: [{ unexpected: true }],
    expectedOutput: { organization: 'example' } }] };
const admissionDouble = () => ({ schema: () => input, sameSchema: () => true,
  accepts: (name, value) => name === 'Output' || Object.keys(value).length === 0,
  runId: 'a'.repeat(64), irId: 'b'.repeat(64), verifyCurrent: async () => {} });
const jsonText = (text) => ({ result: { content: [{ type: 'text', text }] } });
for (const raw of ['{"x":1,"x":2}', '{"x":1,"\\u0078":2}', '1e999', deep(65)]) {
  test('JSON text payloads cannot bypass the raw representation gate: ' + raw.slice(0,30), () => {
    assert.throws(() => readToolPayload(jsonText(raw), { encoding: 'json_text' }), redacted);
  });
}
async function implementation(t, tail = false) {
  const cwd = await mkdtemp(join(tmpdir(), 'mcp-wire-evidence-'));
  t.after(() => rm(cwd, { force: true, recursive: true }));
  const binary = join(cwd, 'server');
  const manifestPath = join(cwd, 'operations.json');
  await writeFile(manifestPath, JSON.stringify(manifest));
  const program = `#!${process.execPath}
import {createInterface} from 'node:readline';
createInterface({input:process.stdin}).on('line',raw=>{
 const m=JSON.parse(raw);if(!Object.hasOwn(m,'id'))return;
 let result={};
 if(m.method==='initialize')result={protocolVersion:m.params.protocolVersion};
 else if(m.method==='tools/list')result={tools:[{name:'identity',inputSchema:{type:'object',additionalProperties:false}}]};
 else if(Object.keys(m.params.arguments).length){
   process.stdout.write(JSON.stringify({jsonrpc:'2.0',id:m.id,error:{code:-32602,message:'invalid'}})+'\\n' + ${JSON.stringify(tail ? '{"unfinished":"SECRET_SENTINEL"' : '')});return;
 }else result={content:[{type:'text',text:'{"organization":"example"}'}]};
 console.log(JSON.stringify({jsonrpc:'2.0',id:m.id,result}));
});`;
  await writeFile(binary, program); await chmod(binary, 0o700);
  return { binary, manifestPath, cwd, admitted: admissionDouble() };
}
test('ambiguous manifest is rejected before authority calls or subprocess start', async (t) => {
  const f = await implementation(t);
  await writeFile(f.manifestPath, JSON.stringify(manifest).replace('{', '{"coverage":"SECRET_SENTINEL",'));
  f.admitted.verifyCurrent = () => assert.fail('must not start admission');
  await assert.rejects(checkImplementation(f), redacted);
});
test('actual conformance with a final partial frame cannot publish passed evidence', async (t) => {
  await assert.rejects(checkImplementation(await implementation(t, true)), /unterminated/);
});
test('successful conformance records the strict wire policy and rechecks after shutdown', async (t) => {
  const f = await implementation(t); let checks = 0;
  f.admitted.verifyCurrent = async () => { checks++; };
  const evidence = await checkImplementation(f);
  assert.equal(evidence.status, 'passed'); assert.equal(evidence.wireJsonPolicy, STRICT_JSON_POLICY);
  assert.equal(evidence.validCalls, 1); assert.equal(evidence.invalidCalls, 1); assert.equal(checks, 2);
});
