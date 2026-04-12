# Security Policy

## Supported versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | Yes       |

Only the latest release receives security fixes.  Upgrade to the current version
before reporting a vulnerability.

## Reporting a vulnerability

**Please do not open a public GitHub issue for security vulnerabilities.**

Report security issues privately by emailing:

> **animeshshaw [at] pm.me**

Include in your report:

- A description of the vulnerability and its potential impact
- Steps to reproduce or a minimal proof-of-concept
- The version of `quantum-safe` you tested against
- Your Python version and operating system

You will receive an acknowledgement within **48 hours** and a full response
within **7 days**.  If the vulnerability is confirmed, a patch will be
prepared and released before public disclosure.

We follow [coordinated disclosure](https://cheatsheetseries.owasp.org/cheatsheets/Vulnerability_Disclosure_Cheat_Sheet.html):
we ask that you give us 90 days to patch before publishing details.

## Security audit

A full internal security audit of v0.1.0 was completed on 2026-04-12.
All 14 findings (3 HIGH, 7 MEDIUM, 4 LOW) were remediated before release.
See [CHANGELOG.md](CHANGELOG.md) for the detailed list of fixes.

## Cryptographic scope

`quantum-safe` delegates all PQC primitives to audited third-party libraries:

- **[liboqs](https://github.com/open-quantum-safe/liboqs)** — ML-KEM, ML-DSA, SLH-DSA
- **[cryptography (pyca)](https://github.com/pyca/cryptography)** — X25519, Ed25519, AES-GCM, HKDF, X.509

Vulnerabilities in those upstream libraries should be reported to their
respective projects.  We track upstream CVEs and update our dependency bounds
promptly.

## Out of scope

- Vulnerabilities requiring physical access to the machine running the library
- Side-channel attacks that require OS-level privilege or co-located hardware access
- Issues in the stub `rustcrypto` backend (it is not yet functional — `is_available()` returns False)
