# Independent review wanted

**No part of this library has had an independent cryptographic review.** It has had two internal
audits (see [SECURITY.md](SECURITY.md)), and the second one found a High-severity flaw that had
shipped in every release up to 0.3.0. Internal audits by the author are not a substitute for another
pair of eyes, so this page says exactly what we would like examined. If you can look at any of it,
please do.

The primitives themselves (ML-KEM, ML-DSA, SLH-DSA from liboqs; X25519, Ed25519, ECDSA, AES-GCM,
HKDF from pyca/cryptography) are upstream's and are **not** what is being asked. The request is about
the *constructions built on top of them*, which are this project's own.

## What to review

Ordered by how much a mistake would matter.

| # | Construction | Where | The claim to check |
|---|---|---|---|
| 1 | **`-v2` signature format**, plain and hybrid | `src/quantum_safe/signatures/_v2.py` | Signing `M2 = u8(len(algo)) \|\| algo \|\| u8(len(ctx)) \|\| ctx \|\| message` with FIPS 204 native context `quantum-safe-sig-v2` (ML-DSA half) and `"quantum-safe-sig-v2" \|\| 0x00 \|\| M2` (Ed25519 or ECDSA P-256 half) gives domain separation between algorithms, contexts and formats; the hybrid `classical(64) \|\| ML-DSA` blob has no way to strip or swap a half; low-S-only raw ECDSA is enough to avoid malleability. Note the stated rule: never use the same key in v1 and v2, because the classical halves are not domain-separated between them. |
| 2 | **Hybrid KEM combiner** (X25519+ML-KEM, P-256+ML-KEM) | `src/quantum_safe/kem/hybrid.py` | `ss = HKDF-SHA256(ikm = ss_x \|\| ss_m, salt = ct_x \|\| ct_m, info = "quantum-safe hybrid KEM v1" \|\| 0x00 \|\| algorithm)` is a sound combiner: it stays secure if either component is secure, and binding the ciphertexts through the HKDF salt is adequate. It is **not** X-Wing and not the TLS `X25519MLKEM768` construction, and has not been checked against NIST SP 800-227's key-combiner guidance. |
| 3 | **Envelope v1 and v2** | `src/quantum_safe/protocols/envelope.py` | Key and nonce derivation and the AAD binding (v2: `2 \|\| len(algo) \|\| algo \|\| extra`); the envelope version is bound to the algorithm on open; the `expected_aad` check is complete. v2 uses HKDF-SHA-384 with info `qs-envelope-enc-v2-cnsa2`. |
| 4 | **Strict parsers** for keys, signatures and sealed messages | `src/quantum_safe/types/keys.py`, `types/signatures.py`, `_internal/serialization.py` | Each parser accepts exactly one encoding of each value, rejects duplicates, trailing bytes and wrong types, and raises one typed error (`KeyParseError`) with no other exception escaping. |
| 5 | **Migration state store** | `src/quantum_safe/migrate/state.py` | The compare-and-set path commits a transition atomically; the history entry is authoritative and `_current` is derived, so a crash between the two writes cannot lose or invent a state. This is concurrency logic, not cryptography. |
| 6 | **Timing-leakage screen** | `tests/bench/bench_leakage.py` | The two-class design, the controls (random-vs-random, public-data calibration, positive control) and the claim that a screen with these controls bounds only gross dependence. |
| 7 | **`StandardJwt` (RFC 9964)** | `src/quantum_safe/protocols/standard_jwt.py` | Strict verification: algorithm must match the key, `crit` refused, canonical base64url signature, claim checks. |

The TypeScript implementation ([quantum-safe-ts](https://github.com/AnimeshShaw/quantum-safe-ts))
implements the same formats and has one more construction, a streaming envelope; its own list is in
that repository's `REVIEW_WANTED.md`. A finding in a shared format affects both.

## What a useful review is

- A written report, even a short one, saying **what you looked at and what you did not**.
- Findings with a concrete failure scenario. A security finding should go through the private route in
  [SECURITY.md](SECURITY.md), not a public issue.
- "I read it and found nothing" is a valid and useful result, if the scope is stated.
- A formal analysis or proof sketch of items 1 to 3 is welcome but not required.

We will publish the report, or a summary you approve, and credit you if you want to be credited (in the
changelog, in any advisory, and in the paper's acknowledgements).

## How to reach us

Email animesh15b@iimk.edu.in, or open an issue with the `review-wanted` label. Say which items you can
take. Partial reviews are fine.

Until at least items 1 to 3 have been reviewed, the documentation will keep saying "not independently
reviewed", and the roadmap will not call any release 1.0.
