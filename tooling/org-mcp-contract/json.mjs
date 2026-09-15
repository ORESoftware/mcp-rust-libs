import { TextDecoder } from 'node:util';

export const STRICT_JSON_POLICY = 'ores.mcp-strict-json/v1';
const MAX_BYTES = 1048576;
const MAX_DEPTH = 64;
const decoder = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });
const invalid = () => { throw new Error('MCP contract: invalid or ambiguous JSON'); };

/** A bounded representation gate, not a schema validator or a new authority.
 * Reject duplicate decoded member names before JSON.parse can discard evidence.
 * Preserve native JSON values, literal array order, and own __proto__ members.
 * Limits can be tightened by consumers, never raised beyond this wire policy.
 */
export function parseStrictJson(input, { maxBytes = MAX_BYTES, maxDepth = MAX_DEPTH } = {}) {
  if (!Number.isSafeInteger(maxBytes) || maxBytes < 1 || maxBytes > MAX_BYTES ||
      !Number.isSafeInteger(maxDepth) || maxDepth < 1 || maxDepth > MAX_DEPTH ||
      !(typeof input === 'string' || input instanceof Uint8Array)) {
    throw new Error('MCP contract: invalid JSON parser configuration');
  }
  const size = typeof input === 'string' ? Buffer.byteLength(input, 'utf8') : input.byteLength;
  if (size > maxBytes) invalid();
  let text;
  try { text = typeof input === 'string' ? input : decoder.decode(input); } catch { invalid(); }
  let i = 0;
  const whitespace = () => { while (i < text.length && /[\x20\t\r\n]/u.test(text[i])) i++; };
  function string() {
    if (text[i] !== '"') invalid();
    const start = i++;
    while (i < text.length) {
      const char = text[i++];
      if (char === '"') {
        let value;
        try { value = JSON.parse(text.slice(start, i)); } catch { invalid(); }
        // Interoperable Unicode scalar strings: do not round-trip lone surrogates
        // through UTF-8 replacement or accept implementation-dependent identities.
        if (!value.isWellFormed()) invalid();
        return value;
      }
      if (char === '\\') {
        if (i === text.length) invalid();
        i++; // JSON.parse of this bounded string checks every escape and control byte.
      }
    }
    invalid();
  }
  function value(depth) {
    whitespace();
    const char = text[i];
    if (char === '{' || char === '[') {
      if (depth >= maxDepth) invalid();
      const isObject = char === '{';
      const end = isObject ? '}' : ']';
      const keys = new Set();
      i++;
      whitespace();
      if (text[i] === end) { i++; return; }
      while (i < text.length) {
        if (isObject) {
          const key = string();
          if (keys.has(key)) invalid();
          keys.add(key);
          whitespace();
          if (text[i++] !== ':') invalid();
        }
        value(depth + 1);
        whitespace();
        if (text[i] === end) { i++; return; }
        if (text[i++] !== ',') invalid();
        whitespace();
      }
      invalid();
    }
    if (char === '"') { string(); return; }
    const rest = text.slice(i);
    const literal = /^(?:true|false|null)/u.exec(rest);
    if (literal) { i += literal[0].length; return; }
    const number = /^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/u.exec(rest);
    if (!number || !Number.isFinite(Number(number[0]))) invalid();
    i += number[0].length;
  }
  value(0);
  whitespace();
  if (i !== text.length) invalid();
  // The scanner deliberately does not construct objects or normalize numbers.
  // JSON.parse preserves own prototype-shaped names without invoking setters.
  try { return JSON.parse(text); } catch { invalid(); }
}
