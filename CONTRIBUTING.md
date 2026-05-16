# Contributing to quantum-safe

## Development setup

```bash
git clone https://github.com/AnimeshShaw/quantum-safe-py
cd quantum-safe-py
pip install -e '.[dev]'
pre-commit install
```

## Project structure

```
src/quantum_safe/
  __init__.py          Public API surface — only add things here deliberately
  _version.py          Single source of version truth
  _internal/           Internal helpers — not part of the public API
  backends/            Cryptographic backend adapters
    base.py            AbstractKEMBackend / AbstractSignatureBackend interfaces
    liboqs.py          liboqs-python adapter
    rustcrypto.py      RustCrypto PyO3 adapter (stub until crate ships)
  types/               Core type system (keys, KEM outputs, signature outputs)
  kem/                 KEM module (KEM, HybridKEM)
  signatures/          Signature module (Sign, HybridSign)
  protocols/           Protocol helpers (Envelope, JWT, TLS, X.509)
  migrate/             Migration tooling (Scanner, Upgrader, StateManager)
  audit/               Audit and compliance (Auditor, SBOM, NIST checker)
tests/
  unit/                Unit tests — no PQC backend required
  integration/         End-to-end tests — classical components only
  bench/               Benchmark harness
```

## Adding a new backend

1. Create `src/quantum_safe/backends/yourbackend.py`
2. Implement `AbstractKEMBackend` and/or `AbstractSignatureBackend`
3. Register in `src/quantum_safe/backends/__init__.py`
4. Add to `_KNOWN_BACKENDS` and the auto-selection priority list
5. Write unit tests in `tests/unit/` using the same pattern as `test_kem.py`

## Adding a new scanner rule

Rules live in `src/quantum_safe/migrate/scanner.py` in the `_RULES` list.
Each rule has:
- `id`: QSxxx (next available number)
- `severity`: Severity.CRITICAL / HIGH / MEDIUM / INFO
- `imports`: set of module paths that activate the rule
- `calls`: set of (module, function) tuples that trigger the rule
- `string_patterns`: set of strings that trigger on string literals

Add a test in `tests/unit/test_migrate.py::TestScanner*`.

## Test markers

```python
@pytest.mark.requires_liboqs   # needs liboqs-python installed
@pytest.mark.slow              # takes more than 5 seconds
```

Run without slow/liboqs tests: `pytest -m "not requires_liboqs and not slow"`

## Commit conventions

- `feat: add X` — new feature
- `fix: correct Y` — bug fix
- `security: patch Z` — security fix (triggers immediate review)
- `bench: measure X` — benchmark changes
- `docs: update X` — documentation only
- `refactor: simplify Y` — no behaviour change

Security-related commits must include a description of the threat model
change in the commit body.

## Cryptographic review

Any change to these files requires a second reviewer with cryptographic
background:

- `types/keys.py` (memory safety, zeroization)
- `types/kem.py` (combiner construction)
- `kem/hybrid.py` (X25519 encap/decap, HKDF construction)
- `signatures/hybrid.py` (Ed25519 signing, hedged mode)
- `protocols/envelope.py` (AEAD construction, AAD)
- `backends/liboqs.py` (context handling, implicit rejection)

## Release process

1. Update `_version.py` and `pyproject.toml` version fields
2. Update `CHANGELOG.md` with release notes
3. `git tag v0.x.y && git push --tags`
4. CI builds and publishes to PyPI automatically
