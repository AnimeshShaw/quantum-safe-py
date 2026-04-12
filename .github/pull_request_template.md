## Summary

<!-- What does this PR do? One paragraph. -->

## Type of change

- [ ] Bug fix
- [ ] Security fix (see SECURITY.md if applicable)
- [ ] New feature
- [ ] Documentation update
- [ ] Benchmark / performance
- [ ] Refactor (no behaviour change)

## Cryptographic review checklist

For changes to `types/keys.py`, `kem/hybrid.py`, `signatures/hybrid.py`,
`backends/`, or `protocols/`:

- [ ] Secret material is zeroized with `ctypes.memset`, not a Python byte-loop
- [ ] Both hybrid sub-operations are evaluated unconditionally before the
      combined result is checked (no early-return timing oracles)
- [ ] New serialization paths include a payload size cap
- [ ] No `__new__` bypass of constructors that run `validate_*` checks
- [ ] Thread-safety implications considered (per-key locks where needed)

## Test coverage

- [ ] Unit tests added or updated
- [ ] Integration tests added if a new backend path is exercised
- [ ] `python -m pytest tests/ -q` passes locally

## Documentation

- [ ] Docstrings updated
- [ ] RST guides updated if user-visible behaviour changed
- [ ] CHANGELOG.md entry added under `[Unreleased]`
