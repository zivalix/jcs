# Security Policy

## Supported Versions

We actively maintain the latest major version with security patches. Previous
versions receive critical fixes only.

| Version | Supported          |
| ------- | ------------------ |
| 1.x     | :white_check_mark: |
| < 1.0   | :x:                |

## Reporting a Vulnerability

The security of `@zivalix/jcs` is critical to us. This library handles JSON
parsing and cryptographic operations: any flaw could compromise data integrity
or availability.

**If you discover a security vulnerability, do not open a public issue.**

### How to Report

Email **security@zivalix.com**.

Please include:

- **Description** — a clear explanation of the vulnerability
- **Impact** — what an attacker could achieve (DoS, data leak, bypass, etc.)
- **Reproduction** — a minimal proof-of-concept payload or code snippet
- **Affected versions** — if known
- **Suggested fix** — optional, but appreciated

### Our Commitment

| Timeline              | Action                                              |
| --------------------- | --------------------------------------------------- |
| < 48 hours            | Acknowledgment of your report                       |
| < 5 business days     | Initial triage and severity assessment              |
| < 30 days             | Fix developed, tested and released (High/Critical)  |
| After the fix ships   | Coordinated public disclosure                       |

We follow responsible disclosure. You will be credited in the advisory unless
you ask to stay anonymous.

## Scope

### In scope

- The core canonicalization engine (`index.ts`)
- WebCrypto HMAC and SHA-256 integration (`hash`, `hmac`, `verifyHmac`)
- Input-validation bypasses (prototype pollution, parser confusion)
- Resource exhaustion on crafted payloads (`maxDepth`, `maxLength`, `maxEntries`)
- Timing weaknesses in signature verification

### Out of scope

- Vulnerabilities in dev dependencies — report those to their own maintainers
- Theoretical attacks without a working proof of concept
- Issues that require physical access or social engineering

## Security Design Notes

The implementation is built with defence in depth:

- **No prototype pollution** — every property is read via
  `Object.getOwnPropertyDescriptor`, never through the prototype chain.
- **No getter execution** — accessor properties are rejected before any user
  code can run.
- **Bounded resources** — depth, output length and member count are capped, and
  the caps are checked before allocation, not after.
- **Timing-safe verification** — signatures are checked with WebCrypto's
  `subtle.verify`, never with `===` on strings. Note that the WebCrypto
  specification does not itself guarantee constant-time behaviour; this library
  does not add its own comparison on top.
- **Zero runtime dependencies** — no supply-chain surface at runtime.

## Past Advisories

None to date. This section will list published CVEs or security patches when
they exist.
