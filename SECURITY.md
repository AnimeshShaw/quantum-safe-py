# Security Policy

## Supported versions

| Version | Supported |
|---------|-----------|
| 0.3.x (latest) | Yes |
| 0.1.x, 0.2.x, 0.3.0 | **No. Upgrade.** |

Only the latest release receives security fixes. **Every release up to and including
0.3.0 has a signature-verification flaw** (a valid signature also verifies for a suffix of the
signed message; see the 0.3.1 entry in [CHANGELOG.md](CHANGELOG.md) and the
[security guide](docs/guides/security.rst)). Upgrade to 0.3.1 or later.

## Reporting a vulnerability

**Please do not open a public GitHub issue for security vulnerabilities.**

Preferred: use GitHub's private reporting. On the repository page choose
**Security, then Report a vulnerability**. Or email:

> **animesh15b [at] iimk.edu.in**

Include in your report:

- A description of the vulnerability and its potential impact
- Steps to reproduce or a minimal proof of concept
- The version of `quantum-safe-py` you tested against
- Your Python version and operating system

You will receive an acknowledgement within **48 hours** and a full response
within **7 days**. If the vulnerability is confirmed, a patch will be
prepared and released before public disclosure, and a GitHub Security Advisory
(with a CVE where one applies) will be published with the fixed release.

We follow [coordinated disclosure](https://cheatsheetseries.owasp.org/cheatsheets/Vulnerability_Disclosure_Cheat_Sheet.html):
we ask that you give us 90 days to patch before publishing details.

## Published advisories

| Advisory | Affected | Fixed in | Summary |
|---|---|---|---|
| [GHSA-wqv6-gm9x-69x8](https://github.com/AnimeshShaw/quantum-safe-py/security/advisories/GHSA-wqv6-gm9x-69x8) | 0.1.0 to 0.3.0 | 0.3.1 | Signature prefix forgery: a signature also verifies for a suffix of the signed message (High) |

## Security audits

- v0.1.0: an internal audit completed on 2026-04-12; all 14 findings (3 HIGH, 7 MEDIUM,
  4 LOW) were remediated before release.
- 0.3.1: a second internal audit (autumn 2026) found six further issues (S1 to S6),
  one of them High (the signature prefix forgery above). All are fixed in 0.3.1 and pinned by
  tests in `tests/security/`. See [CHANGELOG.md](CHANGELOG.md).

Both audits were internal. **The library has not had an independent third-party review, and it
is not validated under NIST CAVP or CMVP.** It delegates the post-quantum primitives to liboqs,
whose own security notes apply; read them before relying on it.

## Cryptographic scope

`quantum-safe-py` delegates all PQC primitives to third-party libraries:

- **[liboqs](https://github.com/open-quantum-safe/liboqs)**: ML-KEM, ML-DSA, SLH-DSA
- **[cryptography (pyca)](https://github.com/pyca/cryptography)**: X25519, Ed25519, ECDSA, AES-GCM, HKDF, X.509

Vulnerabilities in those upstream libraries should be reported to their
respective projects. We track upstream CVEs and update our dependency bounds
promptly. The constructions built on top (hybrid combiner, signature formats, envelope,
migration store) are this project's responsibility and are in scope.

## Out of scope

- Vulnerabilities requiring physical access to the machine running the library
- Side-channel attacks that require OS-level privilege or co-located hardware access.
  The timing screens in `tests/bench/` are a screen for gross dependence, not a
  constant-time proof, and run through the Python binding.
- Issues in the stub `rustcrypto` backend (it is not functional: `is_available()` returns False)
