# Contributing to @zivalix/jcs

Thank you for your interest in contributing!

## Code Style

This project follows strict conventions for security-critical code:

- **Descriptive error messages** — help users debug issues quickly
- **Detailed comments** — especially around security boundaries and RFC compliance
- **Explicit validation** — every input assumption is checked and fails loudly
- **TypeScript strict mode** — no implicit any, all edge cases handled

If you're submitting a PR, please:
1. Match the existing comment and naming style
2. Add tests for any new validation logic
3. Explain security implications in the PR description

## Running Tests

```bash
npm ci
npm run test:coverage
```

Coverage thresholds are enforced in CI (95% statements, 90% branches).

## Security

See [SECURITY.md](./SECURITY.md) for reporting vulnerabilities.
