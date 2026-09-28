# Production-Readiness Rubric — externally derived

## Why this document exists

The first version of the production-gap matrix chose its own eight dimensions.
Those dimensions closely tracked the design principles of the library being
evaluated, so "the library scores Full on all eight" was close to a restatement
of its feature list rather than a measurement. A reviewer can reasonably say the
target was drawn around the arrow, and the limitations section did not address
it — it discussed scoring judgement inside the Partial band, which is a
different problem.

This document fixes that by deriving every dimension from a source outside the
project, recording the exact requirement it comes from, and stating what
evidence would settle each cell. A dimension that cannot be traced to an
external requirement does not belong in the matrix.

Two consequences, both intended:

1. Some dimensions from the original matrix do not survive, because no external
   source requires them.
2. The library does **not** score Full on everything any more. Anchoring "safe
   defaults" to CNSA 2.0 downgrades it, for reasons given under D6.

## Sources

| Tag | Source |
| --- | --- |
| `CNSA2` | NSA, *Commercial National Security Algorithm Suite 2.0* — algorithm specification (May 2025) and FAQ. Mandates ML-KEM-1024 for key establishment, ML-DSA-87 for signatures, AES-256, SHA-384/512, and LMS or XMSS (SP 800-208) for software/firmware signing. Exclusive CNSA 2.0 use by 2030 for software/firmware signing and networking equipment; 2033 for web, cloud and operating systems; NSS transition complete by 2035. |
| `FIPS203/204/205` | NIST FIPS 203 (ML-KEM), 204 (ML-DSA), 205 (SLH-DSA), August 2024. |
| `CMVP` | NIST Cryptographic Module Validation Program — validation runs through tested algorithm implementations (ACVP) as a precondition for a module certificate. |
| `TNO-CADI` | TNO 2025 P11921, *Cryptographic Asset Discovery and Inventory: a market survey and fit-gap analysis* (2025-03-23), funded by CIO Rijk, NCSC-NL and the Ministry of Economic Affairs. Sets requirements for discovery and migration tooling, including automated scanning and inventory, and being agnostic to the target's system design. |
| `IETF-HYB` | IETF draft on hybrid key exchange in TLS 1.3 — domain separation and key-binding requirements for combiners. |

## Dimensions

Each dimension states the external requirement, what counts as evidence, and how
to verify it. Scores are `Full` / `Partial` / `None` / `UNVERIFIED`.

### D1 — CNSA 2.0 key-establishment parameter set
*Source:* `CNSA2`
*Requirement:* ML-KEM-1024 must be available for key establishment.
*Evidence:* the algorithm is selectable through the public API and resolves to a
working implementation.
*Verification:* instantiate the KEM at ML-KEM-1024 and complete an
encapsulate/decapsulate round trip.

### D2 — CNSA 2.0 signature parameter set
*Source:* `CNSA2`
*Requirement:* ML-DSA-87 must be available for signatures.
*Evidence + verification:* as D1, with a sign/verify round trip.

### D3 — Stateful hash-based signing for software/firmware
*Source:* `CNSA2`, SP 800-208
*Requirement:* software and firmware signing uses LMS or XMSS. This is a
separate requirement from D2 and is not satisfied by ML-DSA.
*Evidence:* an LMS or XMSS implementation reachable from the public API, with
state management for the one-time-signature index.
*Note:* this dimension did not exist in the original matrix. It is the clearest
example of a requirement the author-chosen dimensions omitted.

### D4 — Algorithm conformance evidence
*Source:* `CMVP`, `FIPS203/204`
*Requirement:* an implementation claimed as FIPS 203/204 should be testable
against NIST-issued vectors. Note carefully what this dimension does and does
not assert: it scores whether conformance evidence exists, not whether a module
is validated. Validation is a CMVP outcome from an accredited laboratory and no
amount of self-testing produces it.
*Evidence:* published or reproducible results of ACVP vectors run against the
implementation, with the runnable scope stated.
*Verification:* `python tests/conformance/acvp_kat.py` (see that module for
which ACVP test types a high-level binding can and cannot drive).
*Note:* this replaces the original matrix's `FIPS 203/4/5` dimension, which
scored whether the standards were "implemented and exposed" — an API-surface
property that a reader under CNSA 2.0 pressure can easily mistake for
conformance.

### D5 — Hybrid combiner correctness
*Source:* `IETF-HYB`
*Requirement:* a combiner must apply the specified domain separation and key
binding; applications should not have to assemble one.
*Evidence:* a single API call producing a combined secret, with the domain
separation string and input ordering fixed by the library rather than the caller.

### D6 — Defaults appropriate to the stated threat model
*Source:* `CNSA2`
*Requirement:* where a library targets deployments under CNSA 2.0, its defaults
should not fall below the mandated parameter sets, or the gap should be explicit
at the point of use.
*Evidence:* the default algorithm constants, compared against D1/D2.
*Why this changes the result:* this library defaults to ML-KEM-768 and
ML-DSA-65 (`src/quantum_safe/kem/hybrid.py`,
`src/quantum_safe/signatures/algorithms.py:176-177`). Both CNSA 2.0 parameter
sets are supported but neither is the default, so a CNSA-2.0-targeted deployment
that accepts the defaults is non-compliant. Under an external anchor this is
`Partial`, not `Full`. The original "safe defaults" principle judged the defaults
against the project's own reasoning about security margin, which is precisely
the circularity this document is meant to remove.

### D7 — Discovery and inventory capability
*Source:* `TNO-CADI`
*Requirement:* automated scanning and inventory of cryptographic assets,
agnostic to the target's system design.
*Evidence:* a scanner that enumerates cryptographic usage without per-project
configuration, and emits a machine-readable inventory.

### D8 — Migration path for existing material
*Source:* `TNO-CADI`, `CNSA2` timelines
*Requirement:* the 2030/2033 deadlines imply existing keys and stored
ciphertext must be transitionable, not merely that new material can be
generated post-quantum.
*Evidence:* versioned key formats plus tooling that upgrades existing keypairs
or re-encrypts stored data.

### D9 — Protocol integration
*Source:* `CNSA2` timelines (web, cloud, operating systems by 2033)
*Requirement:* usable at the protocol layer, not only as raw primitives.
*Evidence:* at least two of TLS configuration, X.509 certificate generation,
JWT signing, envelope encryption.

## Dimensions from the original matrix that were dropped

| Dropped | Reason |
| --- | --- |
| Unified API | No external source requires a single import. It is an ergonomics preference. |
| WASM Ready | No external source requires a browser target. |
| Dev / CI | Real engineering quality signal, but not an external *requirement*; retaining it in a requirements-derived matrix would reintroduce author-chosen criteria. |

Dropping these is part of the point: three of the original eight dimensions
could not be traced to any external requirement.

## Scoring

Audited 2026-09-28. Python libraries were verified by installing them and
introspecting the API; others from primary sources (upstream repository or
official documentation), cited per row below. `UNVERIFIED` means exactly that,
and is left in rather than guessed.

| Library | D1 | D2 | D3 | D4 | D5 | D6 | D7 | D8 | D9 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| this library | Full | Full | Partial | Partial | Full | **Partial** | Full | Full | Full |
| liboqs-python 0.16.0.1 | Full | Full | None | None | None | n/a | None | None | None |
| pyca/cryptography 48.0.0 | **Full** | **Full** | None | UNVERIFIED | None | n/a | None | None | Full |
| cloudflare/circl | Full | Full | None | None | **Partial** | n/a | None | None | Partial |
| noble-post-quantum | Full | Full | None | **Partial** | **Full** | n/a | None | None | None |
| RustCrypto (ml-kem, ml-dsa, x-wing) | Full | Full | None | UNVERIFIED | **Full** | n/a | None | None | None |
| liboqs-js | Full | Full | None | None | None | n/a | None | None | None |
| Bouncy Castle | Full | Full | **Full** | **Full** | UNVERIFIED | n/a | None | Partial | Full |
| pqcrypto (Rust) | *archived* | *archived* | *archived* | *archived* | *archived* | n/a | *archived* | *archived* | *archived* |
| oqs (Rust) | UNVERIFIED | UNVERIFIED | UNVERIFIED | UNVERIFIED | UNVERIFIED | n/a | UNVERIFIED | UNVERIFIED | UNVERIFIED |

D6 is `n/a` for libraries that expose primitives without defaulting to a
construction; scoring their "defaults" would be scoring a decision they do not
make.

### Evidence

**this library** — D1/D2 verified by round-trip through
`quantum_safe.compliance.cnsa2.hybrid_kem()` and `hybrid_sign()`. D3 Partial: LMS
via the optional `[lms]` extra, XMSS absent, and SP 800-208 additionally requires
key generation in a validated module. D4 Partial: 225/225 runnable ACVP cases
(`results/acvp_kat.json`), but no CMVP validation. D6 Partial: defaults are
ML-KEM-768/ML-DSA-65, below CNSA 2.0.

**liboqs-python 0.16.0.1** — verified by introspection: `ML-KEM-1024` and
`ML-DSA-87` present in enabled mechanisms; no name containing `LMS`/`XMSS`; no
symbol containing `hybrid`; no `tls`/`x509`/`jwt`/`scan` surface. It is a
primitive binding and does not claim otherwise.

**pyca/cryptography 48.0.0** — verified by import:
`asymmetric.mlkem` exposes `MLKEM768/MLKEM1024`, `asymmetric.mldsa` exposes
`MLDSA44/65/87`. `slhdsa` not importable. No hybrid combiner. `x509` present.
**This is a change since the earlier matrix**: the de-facto Python crypto library
now ships FIPS 203/204 primitives, so the Python *algorithm* gap has closed. The
production-layer gap has not.

**cloudflare/circl** — ML-KEM 512/768/1024 (FIPS 203) and ML-DSA 44/65/87
(FIPS 204) per the repository README. `kem/hybrid` provides `X25519MLKEM768()`
alongside older Kyber draft combiners. Scored **Partial** on D5 rather than Full:
the package header states hybrids are "created by simple concatenation" and that
"this approach is not proven secure in broader context", scoping it to TLS, which
is narrower than the domain-separation and key-binding obligations D5 anchors to.
No LMS/XMSS. HPKE and PKI support, no TLS/X.509 stack, so D9 Partial.

**noble-post-quantum** — `ml_kem1024`, `ml_dsa87`, and SLH-DSA variants.
Ships preset hybrid combiners (`ml_kem768_x25519`, `ml_kem768_p256`,
`ml_kem1024_p384`) with an HKDF-SHA256 combiner, so **D5 Full**. README states
"ACVP / wycheproof tests ensure correctness", so **D4 Partial** — it tests against
NIST vectors without claiming validation.

**RustCrypto** — `ml-kem` and `ml-dsa` crates, plus an `x-wing` crate described
as a hybrid PQ KEM (X25519 + ML-KEM-768), so **D5 Full**. Conformance testing not
documented in the repository index; left UNVERIFIED rather than assumed.

**liboqs-js** — `createMLKEM1024()` and `createMLDSA87()` present; SLH-DSA yes,
LMS/XMSS no; no combiner, no protocol layer. Self-described as "meant for
research, prototyping, and experimentation", which is why D4 is None.

**Bouncy Castle** — the strongest row in this table. ML-KEM (FIPS 203), ML-DSA
(FIPS 204), SLH-DSA (FIPS 205), **and both LMS (RFC 8554) and XMSS (RFC 8391)
under SP 800-208**, giving the only **D3 Full**. Holds **CMVP FIPS 140-3
Certificate #4943**, which is D4 Full in the strict sense this rubric means:
validation by an accredited laboratory, not self-testing. X.509/PKIX and TLS
support. D8 Partial (composite key handling, no discovery tooling). Hybrid
combiner not confirmed from the consulted page, so UNVERIFIED.

**pqcrypto (Rust)** — **archived and unmaintained as of 2026-09-16.** The
maintainers direct users to RustCrypto, `aws-lc-rs` or `liboqs-rust`. Scoring a
dead library would misstate the ecosystem, so it is marked archived throughout
and should be replaced in the matrix rather than scored.

**oqs (Rust)** — not audited in this pass.

### What this audit does to the paper's claims

Four claims from the earlier matrix do not survive contact with current versions.

1. **"Hybrid KEM support: 11%, only cloudflare/circl."** Wrong now, and
   substantially so. Combiners exist in circl (`X25519MLKEM768`),
   noble-post-quantum (three presets with an HKDF combiner) and RustCrypto
   (`x-wing`). The headline scarcity figure has to be recomputed, and it will be
   roughly four times larger.
2. **Python's algorithm gap has closed.** pyca/cryptography 48.0.0 ships ML-KEM
   and ML-DSA. Any framing that rests on PQC primitives being unavailable in
   Python is out of date.
3. **Bouncy Castle outscores this library** on D3 (LMS *and* XMSS) and D4 (an
   actual CMVP certificate). The production layer is demonstrably achievable; it
   exists in Java.
4. **Conformance testing is not unique here.** noble-post-quantum already tests
   against ACVP vectors.

What survives, and is worth saying precisely: **in Python specifically, no
library combines a hybrid KEM, migration tooling and protocol helpers.**
pyca/cryptography has primitives and X.509 but no combiner, no migration path and
no discovery; liboqs-python has primitives only. That is a narrower thesis than
"the ecosystem lacks a production layer", and it is the one the evidence supports.

## Prior work this matrix must position against

*A Survey of Post-Quantum Cryptography Support in Cryptographic Libraries*
(arXiv:2508.16078, August 2025) surveys nine libraries — OpenSSL, wolfSSL,
BoringSSL, LibreSSL, Bouncy Castle, libsodium, Crypto++, Botan, MbedTLS — for
support of Kyber, Dilithium, FALCON and SPHINCS+, with attention to performance
and implementation security. Only Bouncy Castle overlaps our library set, and its
dimensions are algorithm-support rather than production-layer: it does not cover
hybrid combiners, migration tooling or protocol integration. The distinction is
real, but any claim that no prior multi-library evaluation exists must be
narrowed accordingly.
