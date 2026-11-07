/**
 * @zivalix/jcs: RFC 8785 JSON Canonicalization Scheme.
 * Zero runtime dependencies. Rejects any value it cannot represent unambiguously.
 * Licensed under MIT. "ZIVALIX" is a trademark of ZIVALIX™ and is not licensed with the code.
 */

export type JcsErrorCode =
  | 'INVALID_VALUE'
  | 'INVALID_OPTION'
  | 'INVALID_KEY'
  | 'LIMIT_EXCEEDED'
  | 'UNSUPPORTED_RUNTIME';

export class JcsError extends TypeError {
  readonly code: JcsErrorCode;
  readonly path: string | undefined;

  constructor(code: JcsErrorCode, message: string, path?: string) {
    super(path === undefined ? `ZIVALIX JCS: ${message}` : `ZIVALIX JCS: ${message} (at ${path})`);
    this.name = 'JcsError';
    this.code = code;
    this.path = path;
  }
}

export interface CanonicalizeOptions {
  /** Maximum nesting depth. Default: 128. */
  readonly maxDepth?: number;
  /** Maximum output length in UTF-16 code units. Default: 16 MiB. */
  readonly maxLength?: number;
  /** Maximum members per object or array. Default: 100 000. */
  readonly maxEntries?: number;
}

type Options = CanonicalizeOptions | null | undefined;

interface Limits {
  readonly maxDepth: number;
  readonly maxLength: number;
  readonly maxEntries: number;
}

const DEFAULT_LIMITS: Limits = Object.freeze({
  maxDepth: 128,
  maxLength: 16 * 1024 * 1024,
  maxEntries: 100_000,
});

const MIN_KEY_BYTES = 32;
const SHA256_HEX = /^[0-9a-f]{64}$/;
const LONE_SURROGATE = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/;
const MAX_KEY_IN_PATH = 40;

type Step = string | number;

interface State {
  readonly limits: Limits;
  readonly ancestors: Set<object>;
  readonly trail: Step[];
  readonly parts: string[];
  length: number;
}

// ---------------------------------------------------------------------------
// Options
// ---------------------------------------------------------------------------

function resolveLimits(options: Options): Limits {
  if (options !== undefined && options !== null) {
    if (typeof options !== 'object' || Array.isArray(options)) {
      throw new JcsError('INVALID_OPTION', 'options must be a plain object');
    }
  }
  const given: CanonicalizeOptions = options ?? {};
  const pick = (name: keyof Limits): number => {
    const value = given[name] ?? DEFAULT_LIMITS[name];
    if (!Number.isSafeInteger(value) || value < 1) {
      throw new JcsError('INVALID_OPTION', `${name} must be a positive safe integer`);
    }
    return value;
  };
  return Object.freeze({
    maxDepth: pick('maxDepth'),
    maxLength: pick('maxLength'),
    maxEntries: pick('maxEntries'),
  });
}

// ---------------------------------------------------------------------------
// Errors and bounded output
// ---------------------------------------------------------------------------

function formatPath(trail: readonly Step[]): string {
  let path = '$';
  for (const step of trail) {
    if (typeof step === 'number') {
      path += `[${step}]`;
    } else {
      // JSON-escaped, so untrusted keys cannot inject control characters into logs.
      const shown = step.length > MAX_KEY_IN_PATH ? `${step.slice(0, MAX_KEY_IN_PATH)}…` : step;
      path += `[${JSON.stringify(shown)}]`;
    }
  }
  return path;
}

function fail(s: State, code: JcsErrorCode, message: string): never {
  throw new JcsError(code, message, formatPath(s.trail));
}

/** Reserves output space, enforcing maxLength on the real output size. */
function reserve(s: State, units: number): void {
  if (s.length + units > s.limits.maxLength) {
    fail(s, 'LIMIT_EXCEEDED', `output exceeds maxLength of ${s.limits.maxLength}`);
  }
  s.length += units;
}

function emit(s: State, text: string): void {
  reserve(s, text.length);
  s.parts.push(text);
}

/** Escapes a string per RFC 8785 §3.2.2.2. JSON.stringify matches it for well-formed text. */
function emitString(s: State, text: string): void {
  if (LONE_SURROGATE.test(text)) {
    fail(s, 'INVALID_VALUE', 'string contains a lone surrogate (not valid I-JSON)');
  }
  // JSON.stringify always emits at least as many units as the raw string (quotes plus
  // any escaping), so a string that already cannot fit can be rejected here, before the
  // escaped copy is allocated.
  if (s.length + text.length + 2 > s.limits.maxLength) {
    fail(s, 'LIMIT_EXCEEDED', `output exceeds maxLength of ${s.limits.maxLength}`);
  }
  const escaped = JSON.stringify(text);
  reserve(s, escaped.length);
  s.parts.push(escaped);
}

// ---------------------------------------------------------------------------
// Structural guards
// ---------------------------------------------------------------------------

/** Reads an own data property through its descriptor. Never invokes a getter. */
function ownData(obj: object, key: PropertyKey): unknown {
  const desc = Object.getOwnPropertyDescriptor(obj, key);
  return desc !== undefined && 'value' in desc ? desc.value : undefined;
}

/**
 * True if `proto` is the intrinsic Object or Array prototype of some realm.
 * A consistency check, not a security boundary: the serializer never calls
 * functions and reads only own data properties. It rejects Map, Date, class
 * instances and similar values that JSON would otherwise flatten silently.
 */
function isIntrinsicPrototype(proto: object, name: 'Object' | 'Array'): boolean {
  const ctor = ownData(proto, 'constructor');
  return typeof ctor === 'function' && ownData(ctor, 'name') === name && ownData(ctor, 'prototype') === proto;
}

function assertKind(obj: object, kind: 'Object' | 'Array', s: State): void {
  const proto = Object.getPrototypeOf(obj) as object | null;
  const ok =
    kind === 'Object'
      ? proto === null || isIntrinsicPrototype(proto, 'Object')
      : proto !== null && isIntrinsicPrototype(proto, 'Array');
  if (!ok) fail(s, 'INVALID_VALUE', 'only plain objects, arrays and JSON primitives are supported');
}

function assertNoEnumerableSymbols(obj: object, s: State): void {
  for (const sym of Object.getOwnPropertySymbols(obj)) {
    if (Object.prototype.propertyIsEnumerable.call(obj, sym)) {
      fail(s, 'INVALID_VALUE', 'enumerable symbol-keyed properties are not allowed');
    }
  }
}

function enter(container: object, s: State): void {
  if (s.ancestors.has(container)) fail(s, 'INVALID_VALUE', 'circular reference');
  if (s.ancestors.size >= s.limits.maxDepth) {
    fail(s, 'LIMIT_EXCEEDED', `maximum depth of ${s.limits.maxDepth} exceeded`);
  }
  s.ancestors.add(container);
}

function leave(container: object, s: State): void {
  s.ancestors.delete(container);
}

/**
 * Shared entry point for both writers: validates kind and symbol keys,
 * tracks the container for circular-reference and depth checks, then hands
 * off to `write` for the container-specific snapshot and emission. Kept
 * intentionally un-nested (no try/finally): on failure the whole `State` is
 * abandoned and the thrown `JcsError` propagates, so there is nothing to
 * unwind. On success, `leave` always runs before returning.
 */
function writeContainer(container: object, kind: 'Object' | 'Array', s: State, write: () => void): void {
  assertKind(container, kind, s);
  assertNoEnumerableSymbols(container, s);
  enter(container, s);
  write();
  leave(container, s);
}

// ---------------------------------------------------------------------------
// Snapshots: each property is read exactly once, then written from the snapshot
// ---------------------------------------------------------------------------

function snapshotArray(arr: unknown[], s: State): unknown[] {
  if (arr.length > s.limits.maxEntries) {
    fail(s, 'LIMIT_EXCEEDED', `array exceeds maxEntries of ${s.limits.maxEntries}`);
  }
  const values: unknown[] = [];
  for (let i = 0; i < arr.length; i++) {
    s.trail.push(i);
    const desc = Object.getOwnPropertyDescriptor(arr, i);
    if (desc === undefined) fail(s, 'INVALID_VALUE', 'sparse arrays (holes) are not allowed');
    if (!('value' in desc)) fail(s, 'INVALID_VALUE', 'accessor properties are not allowed');
    values.push(desc.value);
    s.trail.pop();
  }
  // Named properties on an array would be silently dropped. Refuse them.
  if (Object.keys(arr).length !== arr.length) {
    fail(s, 'INVALID_VALUE', 'arrays may not carry non-index own properties');
  }
  return values;
}

/** Enumerable string keys, undefined values omitted, sorted by UTF-16 code units (§3.2.3). */
function snapshotObject(obj: object, s: State): Array<[string, unknown]> {
  const keys = Object.keys(obj);
  if (keys.length > s.limits.maxEntries) {
    fail(s, 'LIMIT_EXCEEDED', `object exceeds maxEntries of ${s.limits.maxEntries}`);
  }
  const entries: Array<[string, unknown]> = [];
  for (const key of keys) {
    s.trail.push(key);
    const desc = Object.getOwnPropertyDescriptor(obj, key);
    if (desc === undefined || !('value' in desc)) fail(s, 'INVALID_VALUE', 'accessor properties are not allowed');
    if (desc.value !== undefined) entries.push([key, desc.value]);
    s.trail.pop();
  }
  // String comparison orders by UTF-16 code units. Never use localeCompare.
  return entries.sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
}

// ---------------------------------------------------------------------------
// Writers
// ---------------------------------------------------------------------------

function writeArray(arr: unknown[], s: State): void {
  writeContainer(arr, 'Array', s, () => {
    const values = snapshotArray(arr, s);
    emit(s, '[');
    values.forEach((value, index) => {
      if (index > 0) emit(s, ',');
      s.trail.push(index);
      writeValue(value, s);
      s.trail.pop();
    });
    emit(s, ']');
  });
}

function writeObject(obj: object, s: State): void {
  writeContainer(obj, 'Object', s, () => {
    const entries = snapshotObject(obj, s);
    emit(s, '{');
    entries.forEach(([key, value], index) => {
      if (index > 0) emit(s, ',');
      s.trail.push(key);
      emitString(s, key);
      emit(s, ':');
      writeValue(value, s);
      s.trail.pop();
    });
    emit(s, '}');
  });
}

function writeValue(value: unknown, s: State): void {
  switch (typeof value) {
    case 'string':
      emitString(s, value);
      return;
    case 'number':
      if (!Number.isFinite(value)) fail(s, 'INVALID_VALUE', 'NaN and Infinity are not valid JSON numbers');
      // ECMAScript Number::toString is the serialization RFC 8785 §3.2.2.3 specifies. String(-0) is "0".
      emit(s, String(value));
      return;
    case 'boolean':
      emit(s, value ? 'true' : 'false');
      return;
    case 'object':
      if (value === null) emit(s, 'null');
      else if (Array.isArray(value)) writeArray(value, s);
      else writeObject(value, s);
      return;
    case 'undefined':
      fail(s, 'INVALID_VALUE', 'undefined is not a JSON value (inside arrays or at the root)');
      return;
    default:
      fail(s, 'INVALID_VALUE', `unsupported value of type "${typeof value}"`);
  }
}

function serialize(value: unknown, limits: Limits): string {
  const state: State = { limits, ancestors: new Set(), trail: [], parts: [], length: 0 };
  try {
    writeValue(value, state);
    return state.parts.join('');
  } catch (error) {
    // Stack exhaustion (reachable only when maxDepth is raised) and engine string limits surface as RangeError.
    if (error instanceof RangeError) {
      throw new JcsError('LIMIT_EXCEEDED', 'resource limit exceeded (call stack or string size)');
    }
    throw error;
  }
}

function encodeCanonical(value: unknown, limits: Limits): Uint8Array {
  return new TextEncoder().encode(serialize(value, limits));
}

// ---------------------------------------------------------------------------
// Public API: canonical text
// ---------------------------------------------------------------------------

/**
 * Serializes `value` to RFC 8785 canonical JSON text.
 * Input must be plain data. Do not pass Proxy objects or untrusted live objects.
 * @throws {JcsError} for any value that cannot be represented unambiguously.
 */
export function canonicalize(value: unknown, options: Options = {}): string {
  return serialize(value, resolveLimits(options));
}

/** Canonical JSON as UTF-8 bytes. This is what you should sign or hash. */
export function canonicalBytes(value: unknown, options: Options = {}): Uint8Array {
  return encodeCanonical(value, resolveLimits(options));
}

/** True only if `text` is already byte-for-byte its own canonical form. Invalid options still throw. */
export function isCanonical(text: string, options: Options = {}): boolean {
  const limits = resolveLimits(options);
  if (typeof text !== 'string') return false;
  // The canonicalizer enforces maxLength on its own output, so any candidate longer than
  // that can never match it. Short-circuit before paying for a parse of a huge payload.
  if (text.length > limits.maxLength) return false;

  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    return false;
  }
  try {
    return serialize(parsed, limits) === text;
  } catch (error) {
    if (error instanceof JcsError) return false;
    throw error;
  }
}

// ---------------------------------------------------------------------------
// Public API: WebCrypto hash and HMAC
// ---------------------------------------------------------------------------

interface SubtleLike {
  digest(algorithm: string, data: Uint8Array): Promise<ArrayBuffer>;
  importKey(
    format: 'raw',
    keyData: Uint8Array,
    algorithm: { name: string; hash: string },
    extractable: boolean,
    usages: string[],
  ): Promise<unknown>;
  sign(algorithm: string, key: unknown, data: Uint8Array): Promise<ArrayBuffer>;
  verify(algorithm: string, key: unknown, signature: Uint8Array, data: Uint8Array): Promise<boolean>;
}

function subtle(): SubtleLike {
  const api = (globalThis as unknown as { crypto?: { subtle?: SubtleLike } }).crypto?.subtle;
  if (api === undefined) {
    throw new JcsError('UNSUPPORTED_RUNTIME', 'WebCrypto is not available; Node.js 20+ is required');
  }
  return api;
}

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

function fromHex(hex: string): Uint8Array {
  return Uint8Array.from({ length: hex.length / 2 }, (_, i) => Number.parseInt(hex.slice(2 * i, 2 * i + 2), 16));
}

/**
 * Structural check of an HMAC key. Runs before any crypto work, so misuse
 * fails the same way for sign and verify.
 */
function assertKey(key: unknown): asserts key is ArrayBufferView {
  if (!ArrayBuffer.isView(key) || key.byteLength < MIN_KEY_BYTES) {
    throw new JcsError('INVALID_KEY', `HMAC key must be a byte array of at least ${MIN_KEY_BYTES} bytes`);
  }
}

/** Imports an owned copy of the key, then scrubs the copy. The caller's buffer is never retained. */
async function importHmacKey(key: ArrayBufferView, usage: 'sign' | 'verify'): Promise<unknown> {
  const raw = new Uint8Array(key.buffer, key.byteOffset, key.byteLength).slice();
  try {
    return await subtle().importKey('raw', raw, { name: 'HMAC', hash: 'SHA-256' }, false, [usage]);
  } finally {
    raw.fill(0);
  }
}

/**
 * SHA-256 of the canonical form, as 64 lowercase hex characters.
 * An integrity digest, not an authenticator: anyone can recompute it.
 * For webhooks, use `hmac` and `verifyHmac` with a shared secret.
 */
export async function hash(value: unknown, options: Options = {}): Promise<string> {
  const digest = await subtle().digest('SHA-256', canonicalBytes(value, options));
  return toHex(new Uint8Array(digest));
}

/** HMAC-SHA256 of the canonical form, as 64 lowercase hex characters. Key must be at least 32 bytes. */
export async function hmac(key: ArrayBufferView, value: unknown, options: Options = {}): Promise<string> {
  assertKey(key);
  const limits = resolveLimits(options);
  const data = encodeCanonical(value, limits);
  const cryptoKey = await importHmacKey(key, 'sign');
  const signature = await subtle().sign('HMAC', cryptoKey, data);
  return toHex(new Uint8Array(signature));
}

/**
 * Verifies a lowercase-hex signature produced by `hmac`.
 * Programming errors (bad key, bad options) throw. Data problems (malformed
 * signature, non-canonicalizable body) return false. Compare signatures with
 * this function, never with `===`. Verification is not guaranteed constant-time
 * by the WebCrypto specification.
 */
export async function verifyHmac(
  key: ArrayBufferView,
  value: unknown,
  signatureHex: string,
  options: Options = {},
): Promise<boolean> {
  assertKey(key);
  const limits = resolveLimits(options);
  if (typeof signatureHex !== 'string' || !SHA256_HEX.test(signatureHex)) return false;

  let data: Uint8Array;
  try {
    data = encodeCanonical(value, limits);
  } catch (error) {
    if (error instanceof JcsError) return false;
    throw error;
  }
  const cryptoKey = await importHmacKey(key, 'verify');
  return subtle().verify('HMAC', cryptoKey, fromHex(signatureHex), data);
}
