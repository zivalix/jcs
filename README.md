# @zivalix/jcs

[![CI](https://github.com/zivalix/jcs/actions/workflows/ci.yml/badge.svg)](https://github.com/zivalix/jcs/actions/workflows/ci.yml)
[![Coverage](https://img.shields.io/badge/coverage-96%25-brightgreen.svg)](#)
[![Zero Dependencies](https://img.shields.io/badge/dependencies-0-brightgreen.svg)](#)
[![Node](https://img.shields.io/badge/node-%3E%3D20-informational.svg)](#)
[![RFC 8785](https://img.shields.io/badge/RFC-8785-blue.svg)](https://www.rfc-editor.org/rfc/rfc8785)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](./LICENSE)

RFC 8785 JSON Canonicalization Scheme (JCS) with strict validation, and
WebCrypto-based SHA-256 / HMAC-SHA256 helpers over the canonical form.
Zero runtime dependencies.

Built and maintained by [ZIVALIX™](https://zivalix.com).

## Why canonical JSON

`JSON.stringify` is not deterministic across inputs that are semantically
equal: key order, number formatting, and whitespace can all vary. That is
fine for most uses, but it breaks anything that hashes or signs a JSON
payload — webhook signatures, audit log digests, cache keys — because two
semantically identical objects can serialize to different bytes.

[RFC 8785](https://www.rfc-editor.org/rfc/rfc8785) defines a canonical
serialization: the same logical value always produces the same bytes,
regardless of key insertion order or how the value was constructed. This
package implements that specification and adds the primitives you need to
hash or HMAC-sign the result.

## Install

```bash
npm install @zivalix/jcs
```

Requires Node.js 20 or later (for `globalThis.crypto.subtle`).

## Usage

```ts
import { canonicalize, hash, hmac, verifyHmac } from '@zivalix/jcs';

// Deterministic text, regardless of key order
canonicalize({ b: 2, a: 1 }); // '{"a":1,"b":2}'
canonicalize({ a: 1, b: 2 }); // '{"a":1,"b":2}'

// SHA-256 of the canonical form — an integrity digest, not a signature
const digest = await hash({ amount: 100, currency: 'USD' });

// HMAC-SHA256 of the canonical form, for signing and verifying webhooks
const key = crypto.getRandomValues(new Uint8Array(32)); // >= 32 bytes
const signature = await hmac(key, { amount: 100, currency: 'USD' });
const valid = await verifyHmac(key, { currency: 'USD', amount: 100 }, signature);
// true — key order does not affect the result
```

## API

### `canonicalize(value, options?): string`
Serializes `value` to RFC 8785 canonical JSON text. Throws `JcsError` for
any value it cannot represent unambiguously (see "What gets rejected"
below).

### `canonicalBytes(value, options?): Uint8Array`
Canonical JSON as UTF-8 bytes. This is what you should hash or sign —
hashing the string form directly can introduce encoding-related mismatches
across environments.

### `isCanonical(text, options?): boolean`
Returns `true` only if `text` is already byte-for-byte its own canonical
form. Never throws for malformed or hostile `text`; invalid `options` still
throw.

### `hash(value, options?): Promise<string>`
SHA-256 of the canonical form, as 64 lowercase hex characters. This is an
integrity digest: anyone can recompute it. It does not authenticate the
sender. For webhooks or any scenario requiring authentication, use `hmac`
and `verifyHmac` with a shared secret instead.

### `hmac(key, value, options?): Promise<string>`
HMAC-SHA256 of the canonical form, as 64 lowercase hex characters. `key`
must be an `ArrayBufferView` (e.g. `Uint8Array`) of at least 32 bytes.

### `verifyHmac(key, value, signatureHex, options?): Promise<boolean>`
Verifies a signature produced by `hmac`. Programming errors (bad key, bad
options) throw. Data problems (malformed signature, a body that cannot be
canonicalized) return `false`. Always compare signatures with this
function, never with `===` on raw strings.

### `CanonicalizeOptions`
```ts
interface CanonicalizeOptions {
  maxDepth?: number;   // default 128
  maxLength?: number;  // default 16 MiB (UTF-16 code units of output)
  maxEntries?: number; // default 100 000 (members per object or array)
}
```
These bound resource usage against deeply nested, very large, or wide
adversarial inputs. Exceeding any of them throws `JcsError` with code
`LIMIT_EXCEEDED`.

### `JcsError`
Thrown for anything that cannot be represented unambiguously. Extends
`TypeError` and carries:
- `code`: `'INVALID_VALUE' | 'INVALID_OPTION' | 'INVALID_KEY' | 'LIMIT_EXCEEDED' | 'UNSUPPORTED_RUNTIME'`
- `path`: a JSON-Pointer-like string locating the offending value, e.g. `$["a"][1]["b"]`

## What gets rejected

This library never silently drops or coerces data. Instead of guessing what
you meant, it throws. Rejected inputs include:

- `bigint`, `symbol`, and `function` values; `NaN` and `Infinity`
- Sparse arrays (holes) and non-index own properties on arrays
- Getters/accessor properties (never invoked — reading one could run
  attacker-controlled code or return a different value each time)
- Enumerable symbol-keyed properties
- `Map`, `Date`, class instances, and other objects that `JSON.stringify`
  would otherwise flatten or stringify in ways that are easy to misread
- Lone UTF-16 surrogates in strings or keys
- Circular references
- Values exceeding `maxDepth`, `maxLength`, or `maxEntries`

`undefined` is the one exception with special handling, matching
`JSON.stringify`: an object property with an `undefined` value is omitted
from the output. `undefined` anywhere else (array elements, the root value)
is rejected.

Plain objects with a null prototype are accepted (so `Object.create(null)`
works); arrays must keep the intrinsic `Array.prototype` in their chain.
Values from other realms (e.g. `vm.runInNewContext`) are accepted as long as
their prototype matches the *intrinsic* `Object`/`Array` prototype by
constructor name — a plain-data check, not a cross-realm identity check.

## Security notes

- The serializer reads only own data properties through their descriptors
  and never invokes a getter, so a hostile object cannot execute code or
  return a different value on a second read.
- `__proto__` appearing as a JSON key (e.g. via `JSON.parse`) is treated as
  ordinary data, never as prototype mutation.
- `hmac`/`verifyHmac` copy the key into a buffer owned by WebCrypto's key
  import and zero that copy afterwards; the caller's original key buffer is
  never retained by this library.
- WebCrypto's `subtle.verify` is used for signature verification. Its
  timing characteristics are not specified by the WebCrypto specification
  itself; this library does not add its own constant-time comparison on
  top of it.
- `hash` produces an integrity digest, not an authenticator — anyone can
  recompute it from the data. Use `hmac`/`verifyHmac` with a secret key
  whenever the sender needs to be authenticated (e.g. webhooks).

## Development

```bash
npm ci
npm run build          # compiles index.ts -> index.js + index.d.ts
npm run test:coverage  # Jest with coverage thresholds enforced
```

CI runs the same steps on Node 20 and fails the build if coverage drops
below the thresholds declared in `package.json`.

## License

[MIT](./LICENSE) © 2026 ZIVALIX™

"ZIVALIX" and the ZIVALIX logo are trademarks of ZIVALIX™ and are not
licensed under the MIT terms above.

[zivalix.com](https://zivalix.com)

