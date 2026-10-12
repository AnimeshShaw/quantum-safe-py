# quantum-safe-py

Post-quantum cryptography for Python: hybrid key exchange, hybrid signatures, encrypted envelopes, a migration toolkit and a CI-ready audit scanner in one library.

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-green.svg)](LICENSE)
[![Algorithms: FIPS 203/204/205](https://img.shields.io/badge/algorithms-FIPS_203%2F204%2F205-purple.svg)](https://csrc.nist.gov/pubs/fips)
[![CI](https://github.com/AnimeshShaw/quantum-safe-py/actions/workflows/ci.yml/badge.svg)](https://github.com/AnimeshShaw/quantum-safe-py/actions/workflows/ci.yml)
[![Documentation](https://img.shields.io/readthedocs/quantum-safe-py.svg)](https://quantum-safe-py.readthedocs.io/en/latest/)
[![PyPI](https://img.shields.io/pypi/v/quantum-safe-py.svg)](https://pypi.org/project/quantum-safe-py/)
[![PyPI Downloads](https://static.pepy.tech/personalized-badge/quantum-safe-py?period=total&units=INTERNATIONAL_SYSTEM&left_color=BLUE&right_color=GREEN&left_text=downloads)](https://pepy.tech/projects/quantum-safe-py)
[![Roadmap](https://img.shields.io/badge/roadmap-0.4.0-blue.svg)](ROADMAP.md)
[![arXiv](https://img.shields.io/badge/arXiv-preprint-b31b1b.svg)](https://arxiv.org/abs/2605.17061)
[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.23008259.svg)](https://doi.org/10.5281/zenodo.23008259)

## What you get

- **Hybrid by default**: `X25519+ML-KEM-768` key exchange and `Ed25519+ML-DSA-65` signatures, with pure ML-KEM, ML-DSA, SLH-DSA (all 12 sets) and X-Wing available.
- **Envelopes**: KEM + AES-256-GCM in one self-describing, CBOR-encoded message, plus a streaming format for large files.
- **Standards formats**: RFC 9964 JOSE/JWT and COSE_Sign1 for ML-DSA, FIPS 204 native-context signatures.
- **Migration**: scan code for classical crypto, upgrade existing keys to hybrid, track progress per key.
- **Audit**: SARIF and JSON reports, a CycloneDX Cryptographic Bill of Materials, CNSA 2.0 parameter reporting and enforcement.
- **Same bytes as TypeScript**: keys, ciphertexts and signatures are byte-compatible with [quantum-safe-ts](https://github.com/AnimeshShaw/quantum-safe-ts).
- **Tested against NIST vectors**: 638 of 638 runnable ACVP known-answer cases pass.

## Install

```bash
pip install quantum-safe-py                  # classical primitives, formats, scanner, audit
pip install 'quantum-safe-py[liboqs]'        # ML-KEM, ML-DSA, SLH-DSA through liboqs
pip install 'quantum-safe-py[pyca]'          # ML-KEM and ML-DSA through cryptography>=48 (no compiler)
```

Python 3.10 or later. Prebuilt wheels carry liboqs; the other extras (`lms`, `rustcrypto`) are in [Installation](docs/guides/installation.rst).

## Quick start

```python
from quantum_safe import HybridKEM, HybridSign
from quantum_safe.protocols import Envelope

# Key exchange: hybrid X25519 + ML-KEM-768
kem = HybridKEM()
kp = kem.generate_keypair()
ct, shared_secret = kem.encapsulate(kp.public)
assert shared_secret == kem.decapsulate(kp.secret, ct)

# Encrypt to a public key: KEM + AES-256-GCM, and state the AAD you expect on open
sealed = Envelope.seal(b"plaintext", kp.public, aad=b"record-42")
plain = Envelope.open(sealed, kp.secret, expected_aad=b"record-42")

# Sign: hybrid Ed25519 + ML-DSA-65, and state the context you expect on verify
signer = HybridSign()
sk = signer.generate_keypair()
sm = signer.sign(b"important document", sk.secret, context=b"myapp-v1")
signer.verify(sm, sk.public, context=b"myapp-v1")  # raises VerificationError if invalid
```

## Scan, then migrate

```bash
qs-audit scan ./src                                      # find classical crypto, with fix hints
qs-audit scan ./src --format sarif --output audit.sarif  # GitHub Code Scanning
qs-audit cbom ./src --output cbom.json                   # CycloneDX Cryptographic Bill of Materials
qs-audit cnsa2                                           # CNSA 2.0 parameter-set report
qs-migrate status                                        # migration progress per key
```

## Documentation

Everything else is on the documentation site: [quantum-safe-py.readthedocs.io](https://quantum-safe-py.readthedocs.io/en/latest/).

| If you want to...                                           | Read                                                                                                         |
| ----------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------ |
| Try it in five minutes                                      | [Quick start](docs/guides/quickstart.rst)                                                                    |
| Pick the right algorithm, format and token                  | [Choosing what to use](docs/guides/choosing.rst)                                                             |
| Copy a working recipe (encrypt a file, sign a release, ...) | [Cookbook](docs/guides/cookbook.rst)                                                                         |
| Understand keys, contexts, hedging and formats              | [Concepts](docs/guides/concepts.rst)                                                                         |
| Encrypt, sign, issue tokens                                 | [KEM](docs/guides/kem.rst), [Signatures](docs/guides/signatures.rst), [Protocols](docs/guides/protocols.rst) |
| Migrate keys and track progress                             | [Migration](docs/guides/migration.rst)                                                                       |
| Audit a codebase, produce a CBOM, check CNSA 2.0            | [Audit](docs/guides/audit.rst), [CNSA 2.0 and standards](docs/guides/compliance.rst)                         |
| Exchange data with Node.js and browsers                     | [Interoperability](docs/guides/interop.rst)                                                                  |
| Upgrade from an earlier release                             | [Upgrading to 0.4](docs/guides/upgrading-0.4.rst)                                                            |
| Threat model, design notes, report a vulnerability          | [Security](docs/guides/security.rst)                                                                         |
| Benchmarks and methodology                                  | [Benchmarks](docs/guides/benchmarks.rst)                                                                     |
| What changed in each release / what is planned              | [CHANGELOG](CHANGELOG.md), [Roadmap](ROADMAP.md)                                                             |

## How it compares

From a September 2026 audit of nine post-quantum libraries (methodology and sources in the
[production readiness rubric](docs/production_readiness_rubric.md)):

| Capability                               | Ecosystem                | This library                            |
| ---------------------------------------- | ------------------------ | --------------------------------------- |
| Cryptographic discovery and inventory    | 0 of 7 libraries         | CycloneDX CBOM (`qs-audit cbom`)        |
| Hybrid KEM combiner                      | 3 of 6                   | Default mode                            |
| Stateful hash-based signing (LMS / XMSS) | 1 of 7 (Bouncy Castle)   | LMS (`[lms]` extra)                     |
| CMVP certificate                         | 1 of 5 (Bouncy Castle)   | 638 of 638 ACVP known-answer cases pass |
| Migration path for existing keys         | 1 of 7                   | `Upgrader` and a per-key state machine  |
| Protocol helpers (JWT, COSE, TLS, X.509) | 3 of 7                   | `protocols` module                      |
| CNSA 2.0 reporting and enforcement       | none                     | `qs-audit cnsa2`, `cnsa2.enforce()`     |

## Cite this work

```bibtex
@article{shaw2026quantumsafe,
  title     = {quantum-safe: Bridging the Post-Quantum Production Gap with a
               Hybrid-by-Default Python Cryptography Library},
  author    = {Shaw, Animesh},
  journal   = {arXiv preprint arXiv:2605.17061},
  year      = {2026},
  note      = {v2},
  url       = {https://arxiv.org/abs/2605.17061}
}
```

To cite the software itself, use the Zenodo concept DOI [10.5281/zenodo.23008259](https://doi.org/10.5281/zenodo.23008259), which resolves to the latest release.
A machine-readable [CITATION.cff](CITATION.cff) is included for GitHub's "Cite this repository" button.

## Contributing and license

See [CONTRIBUTING.md](CONTRIBUTING.md). Apache 2.0, see [LICENSE](LICENSE).

Built on [Open Quantum Safe / liboqs](https://openquantumsafe.org/), [PyCA cryptography](https://cryptography.io/) and the
[NIST PQC standards](https://csrc.nist.gov/projects/post-quantum-cryptography) (FIPS 203, 204, 205).
