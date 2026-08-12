# Security Policy

## Supported Versions

Security fixes ship in the newest release line. Older lines receive no
backports.

| Version | Supported          |
| ------- | ------------------ |
| 0.2.x   | :white_check_mark: |
| < 0.2.0 | :x:                |

## Reporting a Vulnerability

We take security vulnerabilities seriously. If you discover a security issue, please report it responsibly.

### How to Report

1. **Do NOT open a public GitHub issue** for security vulnerabilities
2. Report through either channel:
   - GitHub private vulnerability reporting: use **Report a vulnerability** on
     the repository's [Security tab](https://github.com/open-e2ee/signal-protocol-js/security)
   - Email: security@open-e2ee.dev
3. Include the following information:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

### Safe Harbor

We will not pursue legal action or law-enforcement referral against
good-faith security research on this codebase. Good faith means: make every
effort to avoid privacy violations and data destruction, use your own accounts
and devices for testing, do not exploit a finding beyond what is needed to
demonstrate it, and give us a reasonable window to remediate before public
disclosure. This applies to research on the SDK itself; testing deployed
third-party applications that use the SDK is governed by those applications'
own policies.

### What to Expect

- **Acknowledgment**: Within 72 hours of your report
- **Initial Assessment**: Within 7 days
- **Resolution Timeline**: Depends on severity
  - Critical: 24-72 hours
  - High: 1-2 weeks
  - Medium: 2-4 weeks
  - Low: Next release cycle

### Disclosure Policy

- We follow responsible disclosure practices
- We will credit reporters (unless anonymity is requested)
- We aim to release patches before public disclosure
- Public disclosure occurs after patch is available

## Security Best Practices

When using this library:

### Key Management

- Store private keys securely (use platform secure storage)
- Never log or transmit private keys
- Implement proper key rotation schedules
- Use the provided `secureZeroBytes()` for key cleanup

### Session Security

- Verify safety numbers with communication partners
- Handle `IdentityKeyChange` events appropriately
- Implement session expiration policies
- Monitor for unusual session patterns

### Backend Security

- Use TLS for all backend communications
- Implement rate limiting on key endpoints
- Use atomic operations for prekey consumption
- Audit backend access logs regularly

## Cryptographic Documentation

This top-level file is the public vulnerability reporting policy. It is not the
source of truth for protocol guarantees or cryptographic primitive selection.

Use these package-local docs for implementation claims:

- [docs/SECURITY.md](./docs/SECURITY.md) for the threat model, reviewability,
  and current security boundaries.
- [ARCHITECTURE.md](./ARCHITECTURE.md) for package boundaries and protocol map.

## Known Limitations

### 1. JavaScript Environment

Running in JavaScript means we cannot guarantee constant-time operations at the
machine level. Some equal-size comparisons and selections use best-effort
fixed-work source patterns, while secret-influenced remainder and compression
arithmetic remains. JIT compilers may introduce further timing variation.

### 2. Memory Security and Secure Zeroing

JavaScript's memory model presents several challenges for secure key handling:

**No Guaranteed Zeroing**: `secureZeroBytes()` overwrites the exact mutable
`Uint8Array` supplied by its caller and reads the result back as a best-effort
source-level measure. It does not prove that an optimizing engine preserved the
write or that no copies exist.

However, JIT compilers may:

- Optimize away the zeroing before our check runs
- Copy values to CPU registers that aren't zeroed
- Leave copies in garbage-collected heap memory

**Garbage Collection**: Sensitive data in JavaScript objects may persist in heap memory until GC runs. We cannot force immediate collection or guarantee cleanup timing.

**ArrayBuffer Copies**: Operations like `buffer.slice()` or `Uint8Array.from()` create copies that we cannot track or zero.

**Mitigations**:

- We best-effort overwrite owned sensitive typed arrays immediately after use
- We avoid unnecessary copies of key material
- We use TypedArrays (which have predictable memory layout) for all cryptographic operations
- We recommend using platform secure storage (Keychain/Keystore) for long-term keys

### 3. Side Channels

Browser/runtime timing attacks are possible. Current source-level mitigations include:

- Full-scan equal-length comparison helpers on selected MAC/ciphertext paths
- Fixed-work derivation of both decapsulation candidates before masked selection
- Fixed-work rejection handling on selected authentication paths

These are not hard constant-time guarantees. Ed25519 signature verification
processes public inputs and is not represented as a timing-safe JavaScript
primitive.

### 4. Hardware Isolation

JavaScript code runs in the same process space as the application. A compromised runtime (browser extension, Node.js module, etc.) could read sensitive memory. Native secure enclaves are not available from JavaScript.
