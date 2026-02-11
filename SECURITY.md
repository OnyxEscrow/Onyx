# Security Policy

## Supported Versions

| Version        | Supported          |
| -------------- | ------------------ |
| 1.0.x-beta     | :white_check_mark: |
| < 1.0.0-beta   | :x:                |

## Reporting a Vulnerability

**Do not open a public issue for security vulnerabilities.**

If you discover a security vulnerability in Onyx, please report it responsibly:

**Email:** security@onyxescrow.com

### What to include

- Description of the vulnerability
- Steps to reproduce
- Affected component (server, WASM module, FROST DKG, CLSAG signing, etc.)
- Potential impact assessment
- Suggested fix (if any)

### Response timeline

- **Acknowledgment:** within 48 hours
- **Initial assessment:** within 7 days
- **Fix or mitigation:** depends on severity (see below)

### Severity levels

| Severity | Description | Target resolution |
| -------- | ----------- | ----------------- |
| Critical | Fund loss, key extraction, signature forgery | 24-72 hours |
| High     | Authentication bypass, escrow state manipulation | 7 days |
| Medium   | Information disclosure, denial of service | 14 days |
| Low      | Minor issues, hardening improvements | Next release |

### Scope

The following components are in scope:

- **FROST DKG implementation** (key generation, share distribution)
- **Threshold CLSAG signing** (round-robin protocol, nonce encryption)
- **Commitment mask derivation** (CMD protocol)
- **Address validation** (checksum verification, network matching)
- **Escrow state machine** (state transitions, authorization)
- **API authentication** (session handling, API keys, CSRF)
- **WASM cryptographic module** (client-side signing)

### Out of scope

- Monero daemon (`monerod`) vulnerabilities — report to [Monero's HackerOne](https://hackerone.com/monero)
- Theoretical attacks requiring quantum computers
- Social engineering
- Denial of service via rate limiting (already mitigated)

### Disclosure policy

We follow coordinated disclosure:

1. Reporter submits vulnerability privately
2. We confirm, assess, and develop a fix
3. Fix is deployed to production
4. Public disclosure after patch is available (credited to reporter unless anonymity is requested)

### Recognition

We maintain a hall of fame for responsible disclosures. Reporters will be credited (with permission) in release notes and in this document.

### PGP Key

For encrypted communication, use our PGP key available at:

```
https://onyxescrow.com/.well-known/security.txt
```
