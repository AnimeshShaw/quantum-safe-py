# Third-party software

quantum-safe-py itself is Apache-2.0 (see `LICENSE`). It uses, and in the binary wheels
redistributes, the following software. The licence of each is the upstream project's
licence; read the upstream text for the exact terms. Versions are the ones a user
installs; check `pip show` for yours.

| Component | How it is used | Licence (upstream statement) | Upstream |
|---|---|---|---|
| liboqs | Compiled library **bundled inside the binary wheels** (`quantum_safe/_vendor/liboqs/`). Provides ML-KEM, ML-DSA, SLH-DSA. | MIT. liboqs also contains code derived from reference implementations under other permissive licences (for example Apache-2.0, CC0 and public-domain dedications); the project documents these per algorithm. | https://github.com/open-quantum-safe/liboqs (`LICENSE.txt`, `docs/`) |
| liboqs-python | Python binding, optional dependency (`[liboqs]` extra), not bundled in the wheel | MIT | https://github.com/open-quantum-safe/liboqs-python |
| cryptography (pyca) | Required dependency: X25519, Ed25519, ECDSA, AES-GCM, HKDF, X.509 | Apache-2.0 OR BSD-3-Clause | https://github.com/pyca/cryptography |
| cbor2 | Required dependency: key serialization | MIT | https://github.com/agronholm/cbor2 |
| pydantic, click, rich | Required dependencies | MIT | their repositories |
| pyhsslms | Optional (`[lms]` extra): LMS / HSS signatures | See the project | https://github.com/russhousley/hss-lms-py |

## Obligation when redistributing the wheels

The MIT licence requires that the copyright notice and permission notice travel with copies
of the software. The liboqs notices are therefore part of what you must keep if you
redistribute a binary wheel. Before each release the maintainer verifies that the wheel
carries the liboqs licence text (see `paper/DEFERRED_WORK.md`, item D12).

## Specifications

The algorithms follow NIST FIPS 203, 204 and 205 (public documents) and RFC 8554 / SP 800-208
for LMS. Nothing from those documents is copied into the code beyond algorithm names and
constants.
