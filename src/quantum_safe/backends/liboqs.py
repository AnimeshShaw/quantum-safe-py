"""
quantum_safe.backends.liboqs
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Backend adapter for liboqs-python (https://github.com/open-quantum-safe/liboqs-python).

liboqs is the Open Quantum Safe project's C library, which is wrapped by the
liboqs-python package.  It has the broadest algorithm coverage of any backend
(BIKE, FrodoKEM, HQC, NTRU as well as all NIST standardized algorithms), so
it's the right choice when you need algorithms beyond the NIST standard set.

For NIST-only deployments (ML-KEM, ML-DSA, SLH-DSA), the RustCrypto backend
is faster and doesn't require a compiled C library.

Installation::

    pip install 'quantum-safe[liboqs]'

The actual install pulls liboqs-python which vendors a pre-built liboqs
binary for the common platforms.  If you're on an unusual architecture you
may need to build liboqs from source — see the OQS docs.

Thread safety: Each liboqs operation creates its own internal context, so
these classes are safe to use from multiple threads.  The oqs Python objects
themselves are NOT thread-safe (they hold mutable C state), so we create a
new one per call rather than sharing instances.
"""

from __future__ import annotations

from typing import ClassVar

from quantum_safe.backends.base import AbstractKEMBackend, AbstractSignatureBackend, AlgorithmInfo
from quantum_safe.exceptions import (
    BackendNotAvailable,
    DecapsulationError,
    KeyGenerationError,
    UnsupportedAlgorithm,
)


# ---------------------------------------------------------------------------
# Algorithm metadata tables
#
# NIST security levels (from FIPS 203/204/205):
#   1 → comparable to AES-128
#   2 → comparable to SHA-256
#   3 → comparable to AES-192
#   4 → comparable to SHA-384
#   5 → comparable to AES-256
#
# Key/ciphertext sizes from the FIPS standards (not from liboqs internals,
# so they're stable references even if the backend changes its encoding).
# ---------------------------------------------------------------------------

_KEM_ALGORITHM_INFO: dict[str, AlgorithmInfo] = {
    "ML-KEM-512": AlgorithmInfo(
        name="ML-KEM-512",
        nist_level=1,
        public_key_size=800,
        secret_key_size=1632,
        ciphertext_size=768,
        is_kem=True,
        is_signature=False,
        is_nist_standard=True,
        notes="FIPS 203, security level 1. Use ML-KEM-768 for new deployments.",
    ),
    "ML-KEM-768": AlgorithmInfo(
        name="ML-KEM-768",
        nist_level=3,
        public_key_size=1184,
        secret_key_size=2400,
        ciphertext_size=1088,
        is_kem=True,
        is_signature=False,
        is_nist_standard=True,
        notes="FIPS 203, security level 3. Recommended default.",
    ),
    "ML-KEM-1024": AlgorithmInfo(
        name="ML-KEM-1024",
        nist_level=5,
        public_key_size=1568,
        secret_key_size=3168,
        ciphertext_size=1568,
        is_kem=True,
        is_signature=False,
        is_nist_standard=True,
        notes="FIPS 203, security level 5. Use when maximum security is required.",
    ),
    # Non-standard algorithms — available through liboqs only
    "BIKE-L1": AlgorithmInfo(
        name="BIKE-L1",
        nist_level=1,
        public_key_size=1541,
        secret_key_size=3114,
        ciphertext_size=1573,
        is_kem=True,
        is_signature=False,
        is_nist_standard=False,
        notes="NIST Round 4 candidate. Not standardized — research use only.",
    ),
    "HQC-128": AlgorithmInfo(
        name="HQC-128",
        nist_level=1,
        public_key_size=2249,
        secret_key_size=2289,
        ciphertext_size=4433,
        is_kem=True,
        is_signature=False,
        is_nist_standard=False,
        notes="NIST Round 4 candidate. Not standardized — research use only.",
    ),
}

_SIGNATURE_ALGORITHM_INFO: dict[str, AlgorithmInfo] = {
    "ML-DSA-44": AlgorithmInfo(
        name="ML-DSA-44",
        nist_level=2,
        public_key_size=1312,
        secret_key_size=2528,
        ciphertext_size=2420,   # signature size
        is_kem=False,
        is_signature=True,
        is_nist_standard=True,
        notes="FIPS 204, security level 2. Smallest ML-DSA variant.",
    ),
    "ML-DSA-65": AlgorithmInfo(
        name="ML-DSA-65",
        nist_level=3,
        public_key_size=1952,
        secret_key_size=4000,
        ciphertext_size=3293,   # signature size
        is_kem=False,
        is_signature=True,
        is_nist_standard=True,
        notes="FIPS 204, security level 3. Recommended default.",
    ),
    "ML-DSA-87": AlgorithmInfo(
        name="ML-DSA-87",
        nist_level=5,
        public_key_size=2592,
        secret_key_size=4864,
        ciphertext_size=4595,   # signature size
        is_kem=False,
        is_signature=True,
        is_nist_standard=True,
        notes="FIPS 204, security level 5. Maximum security.",
    ),
    "SLH-DSA-SHAKE-128s": AlgorithmInfo(
        name="SLH-DSA-SHAKE-128s",
        nist_level=1,
        public_key_size=32,
        secret_key_size=64,
        ciphertext_size=7856,   # signature size (small variant is slow, small sigs)
        is_kem=False,
        is_signature=True,
        is_nist_standard=True,
        notes="FIPS 205, security level 1, small signatures. Very slow to sign.",
    ),
    "SLH-DSA-SHAKE-128f": AlgorithmInfo(
        name="SLH-DSA-SHAKE-128f",
        nist_level=1,
        public_key_size=32,
        secret_key_size=64,
        ciphertext_size=17088,  # signature size (fast variant is fast, bigger sigs)
        is_kem=False,
        is_signature=True,
        is_nist_standard=True,
        notes="FIPS 205, security level 1, fast signing. Larger signatures.",
    ),
}

# liboqs uses different name formats internally. This maps our canonical names
# to the names liboqs expects.  We keep our names aligned with the FIPS
# standards, which use hyphens and no spaces.
_KEM_LIBOQS_NAMES: dict[str, str] = {
    "ML-KEM-512": "ML-KEM-512",
    "ML-KEM-768": "ML-KEM-768",
    "ML-KEM-1024": "ML-KEM-1024",
    "BIKE-L1": "BIKE-L1",
    "HQC-128": "HQC-128",
}

_SIG_LIBOQS_NAMES: dict[str, str] = {
    "ML-DSA-44": "ML-DSA-44",
    "ML-DSA-65": "ML-DSA-65",
    "ML-DSA-87": "ML-DSA-87",
    "SLH-DSA-SHAKE-128s": "SPHINCS+-SHAKE-128s-simple",  # liboqs name differs
    "SLH-DSA-SHAKE-128f": "SPHINCS+-SHAKE-128f-simple",
}


def _import_oqs() -> "object":
    """Import the oqs module or raise BackendNotAvailable."""
    try:
        import oqs  # type: ignore[import]
        return oqs
    except ImportError as exc:
        raise BackendNotAvailable("liboqs") from exc


class LiboqsKEMBackend(AbstractKEMBackend):
    """KEM backend using liboqs-python."""

    name: ClassVar[str] = "liboqs"

    def supported_algorithms(self) -> list[AlgorithmInfo]:
        """Return algorithms supported by this backend.

        We only return algorithms that are actually enabled in the installed
        liboqs build — some builds omit BIKE or HQC for size/license reasons.
        """
        oqs = _import_oqs()
        enabled = set(oqs.get_enabled_kem_mechanisms())

        result = []
        for canonical, liboqs_name in _KEM_LIBOQS_NAMES.items():
            if liboqs_name in enabled:
                info = _KEM_ALGORITHM_INFO.get(canonical)
                if info:
                    result.append(info)

        return result

    def _liboqs_name(self, algorithm: str) -> str:
        name = _KEM_LIBOQS_NAMES.get(algorithm)
        if name is None:
            raise UnsupportedAlgorithm(
                algorithm,
                available=list(_KEM_LIBOQS_NAMES.keys()),
            )
        return name

    def keygen(self, algorithm: str) -> tuple[bytes, bytes]:
        """Generate an ML-KEM (or other KEM) key pair.

        Returns (public_key_bytes, secret_key_bytes).
        """
        oqs = _import_oqs()
        liboqs_name = self._liboqs_name(algorithm)

        try:
            # Each call creates a fresh oqs.KeyEncapsulation context.
            # This is slightly slower than reusing one, but avoids shared
            # mutable state across threads.
            kem = oqs.KeyEncapsulation(liboqs_name)
            pub = kem.generate_keypair()
            sec = kem.export_secret_key()
            return bytes(pub), bytes(sec)
        except Exception as exc:
            # oqs raises generic Exception types — we wrap them
            if "not supported" in str(exc).lower():
                raise UnsupportedAlgorithm(algorithm) from exc
            raise KeyGenerationError(
                f"liboqs keygen failed for {algorithm}: {exc}",
                algorithm=algorithm,
            ) from exc

    def encapsulate(self, algorithm: str, public_key: bytes) -> tuple[bytes, bytes]:
        """Encapsulate a shared secret under the given public key.

        Returns (ciphertext_bytes, shared_secret_bytes).
        """
        oqs = _import_oqs()
        liboqs_name = self._liboqs_name(algorithm)

        try:
            kem = oqs.KeyEncapsulation(liboqs_name)
            ciphertext, shared_secret = kem.encap_secret(public_key)
            return bytes(ciphertext), bytes(shared_secret)
        except Exception as exc:
            from quantum_safe.exceptions import CryptoError
            raise CryptoError(
                f"liboqs encapsulation failed for {algorithm}: {exc}",
                algorithm=algorithm,
            ) from exc

    def decapsulate(
        self, algorithm: str, secret_key: bytes, ciphertext: bytes
    ) -> bytes:
        """Decapsulate a shared secret from a ciphertext.

        Returns shared_secret_bytes.

        IMPORTANT: liboqs ML-KEM implements implicit rejection (per FIPS 203
        §6.3) — a malformed ciphertext returns a pseudorandom value rather
        than raising an exception. We check the output length to detect the
        most obvious failure modes, but we cannot distinguish a bad ciphertext
        from a good one by inspecting the output.
        """
        oqs = _import_oqs()
        liboqs_name = self._liboqs_name(algorithm)

        try:
            kem = oqs.KeyEncapsulation(liboqs_name, secret_key=secret_key)
            shared_secret = kem.decap_secret(ciphertext)
            result = bytes(shared_secret)
            # 32 bytes expected for all standardized algorithms
            if len(result) not in (32, 64):
                raise DecapsulationError(algo=algorithm)
            return result
        except DecapsulationError:
            raise
        except Exception as exc:
            raise DecapsulationError(algo=algorithm) from exc

    def is_available(self) -> bool:
        """Check if liboqs is importable and has at least ML-KEM-768."""
        try:
            oqs = _import_oqs()
            enabled = oqs.get_enabled_kem_mechanisms()
            return "ML-KEM-768" in enabled
        except Exception:  # noqa: BLE001
            return False


class LiboqsSignatureBackend(AbstractSignatureBackend):
    """Signature backend using liboqs-python."""

    name: ClassVar[str] = "liboqs"

    def supported_algorithms(self) -> list[AlgorithmInfo]:
        oqs = _import_oqs()
        enabled = set(oqs.get_enabled_sig_mechanisms())

        result = []
        for canonical, liboqs_name in _SIG_LIBOQS_NAMES.items():
            if liboqs_name in enabled:
                info = _SIGNATURE_ALGORITHM_INFO.get(canonical)
                if info:
                    result.append(info)
        return result

    def _liboqs_name(self, algorithm: str) -> str:
        name = _SIG_LIBOQS_NAMES.get(algorithm)
        if name is None:
            raise UnsupportedAlgorithm(
                algorithm,
                available=list(_SIG_LIBOQS_NAMES.keys()),
            )
        return name

    def keygen(self, algorithm: str) -> tuple[bytes, bytes]:
        oqs = _import_oqs()
        liboqs_name = self._liboqs_name(algorithm)
        try:
            sig = oqs.Signature(liboqs_name)
            pub = sig.generate_keypair()
            sec = sig.export_secret_key()
            return bytes(pub), bytes(sec)
        except Exception as exc:
            raise KeyGenerationError(
                f"liboqs signature keygen failed for {algorithm}: {exc}",
                algorithm=algorithm,
            ) from exc

    def sign(
        self,
        algorithm: str,
        secret_key: bytes,
        message: bytes,
        context: bytes = b"",
    ) -> bytes:
        """Sign a message.

        FIPS 204 §5.2 specifies that the context is prepended to the message
        before hashing. liboqs-python's Signature.sign() doesn't directly
        expose the context parameter in older versions, so we prepend it
        manually using the format::

            context_len (1 byte) || context || message

        This is consistent with the HashML-DSA construction in FIPS 204 §5.4.
        When liboqs exposes context natively (v0.11+), we'll use that instead.
        """
        oqs = _import_oqs()
        liboqs_name = self._liboqs_name(algorithm)

        if len(context) > 255:
            raise ValueError(f"context must be ≤255 bytes, got {len(context)}")

        # Prepend context using length-prefixed format
        msg_with_context = bytes([len(context)]) + context + message

        try:
            sig_obj = oqs.Signature(liboqs_name, secret_key=secret_key)
            signature = sig_obj.sign(msg_with_context)
            return bytes(signature)
        except Exception as exc:
            from quantum_safe.exceptions import CryptoError
            raise CryptoError(
                f"liboqs signing failed for {algorithm}: {exc}",
                algorithm=algorithm,
            ) from exc

    def verify(
        self,
        algorithm: str,
        public_key: bytes,
        message: bytes,
        signature: bytes,
        context: bytes = b"",
    ) -> bool:
        """Verify a signature. Returns True if valid, False if not."""
        oqs = _import_oqs()
        liboqs_name = self._liboqs_name(algorithm)

        if len(context) > 255:
            return False

        msg_with_context = bytes([len(context)]) + context + message

        try:
            sig_obj = oqs.Signature(liboqs_name)
            return bool(sig_obj.verify(msg_with_context, signature, public_key))
        except Exception:  # noqa: BLE001
            # liboqs raises on invalid signatures in some versions —
            # we normalise to bool return
            return False

    def is_available(self) -> bool:
        try:
            oqs = _import_oqs()
            enabled = oqs.get_enabled_sig_mechanisms()
            return "ML-DSA-65" in enabled
        except Exception:  # noqa: BLE001
            return False
