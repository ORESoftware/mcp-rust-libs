import { spawn } from 'node:child_process';
import { isAbsolute } from 'node:path';
import { parseStrictJson } from './json.mjs';

const object = (value) => value !== null && typeof value === 'object' && !Array.isArray(value);

/** Bounded test transport. No shell, inherited credentials, or server diagnostics in errors. */
export function connectStdio(binary, { cwd, timeoutMs = 5000, maxBytes = 1048576, args = [] } = {}) {
  if (!isAbsolute(binary) || !Number.isSafeInteger(timeoutMs) || timeoutMs < 1 ||
      !Number.isSafeInteger(maxBytes) || maxBytes < 1 || !Array.isArray(args) ||
      !args.every((value) => typeof value === 'string')) {
    throw new Error('MCP contract: invalid transport configuration');
  }
  const child = spawn(binary, args, { cwd, env: {}, shell: false, stdio: ['pipe', 'pipe', 'pipe'] });
  let buffer = Buffer.alloc(0);
  let bytes = 0;
  let serial = 0;
  let failure;
  let closing = false;
  let exited = false;
  const pending = new Map();
  const closed = new Promise((resolve) => child.once('close', () => { exited = true; resolve(); }));
  function fail(code) {
    failure ??= new Error(`MCP contract: ${code}`);
    for (const { reject, timer } of pending.values()) { clearTimeout(timer); reject(failure); }
    pending.clear();
    child.kill('SIGKILL');
  }
  function count(chunk) {
    bytes += chunk.length;
    if (bytes > maxBytes) { fail('server output exceeded bound'); return false; }
    return !failure;
  }
  child.on('error', () => fail('server could not start'));
  child.stdin.on('error', () => { if (!closing) fail('server input failed'); });
  child.once('close', () => {
    if (buffer.length) fail('unterminated JSON-RPC frame');
    if (!closing) fail('server exited before suite completed');
  });
  child.stderr.on('data', count); // Discard, but bound stderr as well as stdout.
  child.stdout.on('data', (chunk) => {
    if (!count(chunk)) return;
    buffer = Buffer.concat([buffer, chunk]);
    let newline;
    while ((newline = buffer.indexOf(10)) !== -1) {
      const line = buffer.subarray(0, newline);
      buffer = buffer.subarray(newline + 1);
      let message;
      try { message = parseStrictJson(line); } catch { fail('invalid or ambiguous JSON stdout'); return; }
      if (!object(message) || message.jsonrpc !== '2.0') { fail('invalid JSON-RPC envelope'); return; }
      if (!Object.hasOwn(message, 'id')) {
        if (typeof message.method !== 'string' || Object.hasOwn(message, 'result') ||
            Object.hasOwn(message, 'error') || (Object.hasOwn(message, 'params') &&
              !object(message.params) && !Array.isArray(message.params))) {
          fail('invalid JSON-RPC notification'); return;
        }
        continue;
      }
      const request = pending.get(message.id);
      if (!request || Object.hasOwn(message, 'method') ||
          Object.hasOwn(message, 'result') === Object.hasOwn(message, 'error') ||
          (Object.hasOwn(message, 'error') && (!object(message.error) ||
            !Number.isSafeInteger(message.error.code) || typeof message.error.message !== 'string'))) {
        fail('unexpected JSON-RPC response'); return;
      }
      pending.delete(message.id);
      clearTimeout(request.timer);
      request.resolve(message);
    }
  });
  function write(message) {
    if (failure) throw failure;
    if (closing || exited) throw new Error('MCP contract: transport closed');
    const line = `${JSON.stringify(message)}\n`;
    if (Buffer.byteLength(line) > maxBytes) throw new Error('MCP contract: request exceeded bound');
    child.stdin.write(line);
  }
  return {
    request(method, params = {}) {
      if (failure) return Promise.reject(failure);
      const id = ++serial;
      return new Promise((resolve, reject) => {
        const timer = setTimeout(() => fail('request timed out'), timeoutMs);
        pending.set(id, { resolve, reject, timer });
        try { write({ jsonrpc: '2.0', id, method, params }); }
        catch (error) { clearTimeout(timer); pending.delete(id); reject(error); }
      });
    },
    notify(method, params = {}) { write({ jsonrpc: '2.0', method, params }); },
    assertHealthy() { if (failure) throw failure; },
    async close() {
      closing = true;
      for (const { reject, timer } of pending.values()) {
        clearTimeout(timer); reject(new Error('MCP contract: transport closed'));
      }
      pending.clear();
      if (!exited) {
        child.stdin.end();
        child.kill('SIGTERM');
        const timer = setTimeout(() => child.kill('SIGKILL'), 1000);
        await closed;
        clearTimeout(timer);
      }
    },
  };
}
