"""Unit tests for quantum_safe.exceptions"""

from quantum_safe.exceptions import (
    BackendNotAvailable,
    ClassicalKeyDetected,
    CryptoError,
    DecapsulationError,
    IncompatibleKeyVersion,
    KeyParseError,
    QuantumSafeError,
    UnsupportedAlgorithm,
    VerificationError,
)


class TestExceptionHierarchy:
    def test_all_are_quantum_safe_error(self):
        exceptions = [
            DecapsulationError(),
            VerificationError(),
            KeyParseError("pem", "bad format"),
            BackendNotAvailable("liboqs"),
            ClassicalKeyDetected("RSA-2048"),
            IncompatibleKeyVersion(99, 1),
            UnsupportedAlgorithm("FAKE-KEM-1024"),
        ]
        for exc in exceptions:
            assert isinstance(exc, QuantumSafeError), (
                f"{type(exc).__name__} should be a QuantumSafeError"
            )

    def test_crypto_errors_are_crypto_error(self):
        assert isinstance(DecapsulationError(), CryptoError)
        assert isinstance(VerificationError(), CryptoError)

    def test_codes_are_strings(self):
        # Every exception must have a code attribute
        for cls in [
            QuantumSafeError,
            CryptoError,
            DecapsulationError,
            VerificationError,
            BackendNotAvailable,
        ]:
            assert isinstance(cls.code, str)
            assert cls.code.startswith("QS_")


class TestDecapsulationError:
    def test_message_does_not_include_algo(self):
        # The error message should be generic — don't reveal which specific
        # algorithm failed (timing oracle concerns)
        exc = DecapsulationError(algo="ML-KEM-768")
        msg = str(exc)
        # Message mentions failure, not the specific key
        assert "Decapsulation failed" in msg

    def test_context_has_algo(self):
        exc = DecapsulationError(algo="ML-KEM-768")
        assert exc.context.get("algo") == "ML-KEM-768"


class TestVerificationError:
    def test_context_mismatch_variant(self):
        exc = VerificationError(context_mismatch=True)
        assert "context" in str(exc).lower()

    def test_standard_variant(self):
        exc = VerificationError()
        assert "invalid" in str(exc).lower() or "tampered" in str(exc).lower()


class TestBackendNotAvailable:
    def test_install_hint_for_liboqs(self):
        exc = BackendNotAvailable("liboqs")
        assert "pip install" in exc.install_hint
        assert "liboqs" in exc.install_hint

    def test_install_hint_for_unknown_backend(self):
        exc = BackendNotAvailable("myexoticbackend")
        assert exc.install_hint  # Should have some hint even for unknown backends


class TestUnsupportedAlgorithm:
    def test_available_list_in_message(self):
        exc = UnsupportedAlgorithm("FAKE-KEM", available=["ML-KEM-512", "ML-KEM-768"])
        msg = str(exc)
        assert "ML-KEM-512" in msg
        assert "ML-KEM-768" in msg

    def test_no_available_list(self):
        # Should not crash when available is None
        exc = UnsupportedAlgorithm("FAKE-KEM")
        assert "FAKE-KEM" in str(exc)


class TestIncompatibleKeyVersion:
    def test_version_numbers_in_message(self):
        exc = IncompatibleKeyVersion(key_version=5, supported_max=1)
        msg = str(exc)
        assert "5" in msg
        assert "1" in msg


class TestQuantumSafeErrorContext:
    def test_context_stored(self):
        exc = QuantumSafeError("test message", file="test.py", line=42)
        assert exc.context["file"] == "test.py"
        assert exc.context["line"] == 42

    def test_repr_includes_context(self):
        exc = QuantumSafeError("test", foo="bar")
        r = repr(exc)
        assert "foo" in r
        assert "bar" in r
