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

    pip install 'quantum-safe-py[liboqs]'

The actual install pulls liboqs-python, which on its own does not ship a
prebuilt liboqs binary — on first ``import oqs`` it uses a system liboqs if
found, or downloads and compiles liboqs from source (needs git, CMake, and a
C compiler). Our own released wheels bundle a precompiled liboqs binary for
common platforms (Linux x86_64, Windows x64, macOS arm64 14+) — see
``hatch_build.py`` and ``_vendored_liboqs_dir()`` below — so installation is
compiler-free there. Elsewhere, liboqs-python's normal build-from-source path
applies; see the OQS docs.

Thread safety: Each liboqs operation creates its own internal context, so
these classes are safe to use from multiple threads.  The oqs Python objects
themselves are NOT thread-safe (they hold mutable C state), so we create a
new one per call rather than sharing instances.
"""

from __future__ import annotations

import ctypes
import functools
import importlib.resources
import os
from pathlib import Path
from typing import Any, ClassVar

from quantum_safe._liboqs_version import LIBOQS_VERSION
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
        secret_key_size=5223,
        ciphertext_size=1573,
        is_kem=True,
        is_signature=False,
        is_nist_standard=False,
        notes="NIST Round 4 candidate. Not standardized.",
    ),
    "BIKE-L3": AlgorithmInfo(
        name="BIKE-L3",
        nist_level=3,
        public_key_size=3083,
        secret_key_size=10105,
        ciphertext_size=3115,
        is_kem=True,
        is_signature=False,
        is_nist_standard=False,
        notes="NIST Round 4 candidate. Not standardized.",
    ),
    "BIKE-L5": AlgorithmInfo(
        name="BIKE-L5",
        nist_level=5,
        public_key_size=5122,
        secret_key_size=16494,
        ciphertext_size=5154,
        is_kem=True,
        is_signature=False,
        is_nist_standard=False,
        notes="NIST Round 4 candidate. Not standardized.",
    ),
    "HQC-128": AlgorithmInfo(
        name="HQC-128",
        nist_level=1,
        public_key_size=2241,
        secret_key_size=2321,
        ciphertext_size=4433,
        is_kem=True,
        is_signature=False,
        is_nist_standard=False,
        notes="Selected by NIST (2025); standard in preparation.",
    ),
    "HQC-192": AlgorithmInfo(
        name="HQC-192",
        nist_level=3,
        public_key_size=4514,
        secret_key_size=4602,
        ciphertext_size=8978,
        is_kem=True,
        is_signature=False,
        is_nist_standard=False,
        notes="Selected by NIST (2025); standard in preparation.",
    ),
    "HQC-256": AlgorithmInfo(
        name="HQC-256",
        nist_level=5,
        public_key_size=7237,
        secret_key_size=7333,
        ciphertext_size=14421,
        is_kem=True,
        is_signature=False,
        is_nist_standard=False,
        notes="Selected by NIST (2025); standard in preparation.",
    ),
}

_SIGNATURE_ALGORITHM_INFO: dict[str, AlgorithmInfo] = {
    "ML-DSA-44": AlgorithmInfo(
        name="ML-DSA-44",
        nist_level=2,
        public_key_size=1312,
        secret_key_size=2560,
        ciphertext_size=2420,  # signature size
        is_kem=False,
        is_signature=True,
        is_nist_standard=True,
        notes="FIPS 204, security level 2. Smallest ML-DSA variant.",
    ),
    "ML-DSA-65": AlgorithmInfo(
        name="ML-DSA-65",
        nist_level=3,
        public_key_size=1952,
        secret_key_size=4032,
        ciphertext_size=3309,  # signature size
        is_kem=False,
        is_signature=True,
        is_nist_standard=True,
        notes="FIPS 204, security level 3. Recommended default.",
    ),
    "ML-DSA-87": AlgorithmInfo(
        name="ML-DSA-87",
        nist_level=5,
        public_key_size=2592,
        secret_key_size=4896,
        ciphertext_size=4627,  # signature size
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
        ciphertext_size=7856,  # signature size (small variant is slow, small sigs)
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


def _register_slh_dsa_info() -> None:
    """Add the SLH-DSA sets the table above does not list, from the signature registry."""
    from quantum_safe.signatures.algorithms import SIGNATURE_ALGORITHMS

    for name, spec in SIGNATURE_ALGORITHMS.items():
        if name.startswith("SLH-DSA-") and name not in _SIGNATURE_ALGORITHM_INFO:
            small = name.endswith("s")
            _SIGNATURE_ALGORITHM_INFO[name] = AlgorithmInfo(
                name=name,
                nist_level=int(spec.nist_level),
                public_key_size=spec.public_key_bytes,
                secret_key_size=spec.secret_key_bytes,
                ciphertext_size=spec.signature_bytes,  # signature size
                is_kem=False,
                is_signature=True,
                is_nist_standard=True,
                notes=(
                    f"FIPS 205, security level {int(spec.nist_level)}, "
                    + ("small signatures. Very slow to sign." if small else "fast signing.")
                ),
            )


_register_slh_dsa_info()

# liboqs uses different name formats internally. This maps our canonical names
# to the names liboqs expects.  We keep our names aligned with the FIPS
# standards, which use hyphens and no spaces.
#
# A name maps to the candidates a liboqs build may call it, newest first: liboqs 0.16 renamed the
# HQC mechanisms from HQC-128/192/256 to HQC-1/3/5 (and changed their sizes with the 2025
# specification). The registry keeps one stable public name.
_KEM_LIBOQS_NAMES: dict[str, tuple[str, ...]] = {
    "ML-KEM-512": ("ML-KEM-512",),
    "ML-KEM-768": ("ML-KEM-768",),
    "ML-KEM-1024": ("ML-KEM-1024",),
    "BIKE-L1": ("BIKE-L1",),
    "BIKE-L3": ("BIKE-L3",),
    "BIKE-L5": ("BIKE-L5",),
    "HQC-128": ("HQC-1", "HQC-128"),
    "HQC-192": ("HQC-3", "HQC-192"),
    "HQC-256": ("HQC-5", "HQC-256"),
}

_SIG_LIBOQS_NAMES: dict[str, str] = {
    "ML-DSA-44": "ML-DSA-44",
    "ML-DSA-65": "ML-DSA-65",
    "ML-DSA-87": "ML-DSA-87",
    # FIPS 205 SLH-DSA. These previously mapped to "SPHINCS+-...-simple", which
    # is the pre-standard round-3 submission, not FIPS 205. The two share
    # parameter sizes but are NOT interchangeable: FIPS 205 prepends a
    # domain-separation prefix to the message, so a SPHINCS+ signature does not
    # verify under SLH-DSA and vice versa (asserted in the test suite). Anything
    # selecting these names for FIPS 205 compliance must reach the SLH_DSA_*
    # mechanisms below.
    "SLH-DSA-SHAKE-128s": "SLH_DSA_PURE_SHAKE_128S",
    "SLH-DSA-SHAKE-128f": "SLH_DSA_PURE_SHAKE_128F",
    "SLH-DSA-SHAKE-192s": "SLH_DSA_PURE_SHAKE_192S",
    "SLH-DSA-SHAKE-192f": "SLH_DSA_PURE_SHAKE_192F",
    "SLH-DSA-SHAKE-256s": "SLH_DSA_PURE_SHAKE_256S",
    "SLH-DSA-SHAKE-256f": "SLH_DSA_PURE_SHAKE_256F",
    "SLH-DSA-SHA2-128s": "SLH_DSA_PURE_SHA2_128S",
    "SLH-DSA-SHA2-128f": "SLH_DSA_PURE_SHA2_128F",
    "SLH-DSA-SHA2-192s": "SLH_DSA_PURE_SHA2_192S",
    "SLH-DSA-SHA2-192f": "SLH_DSA_PURE_SHA2_192F",
    "SLH-DSA-SHA2-256s": "SLH_DSA_PURE_SHA2_256S",
    "SLH-DSA-SHA2-256f": "SLH_DSA_PURE_SHA2_256F",
}

# Pre-standard round-3 SPHINCS+ mechanisms, kept reachable under explicit
# names so that callers who genuinely need the legacy algorithm can ask for it
# without it masquerading as a FIPS 205 standard.
_LEGACY_SPHINCS_NAMES: dict[str, str] = {
    "SPHINCS+-SHAKE-128s": "SPHINCS+-SHAKE-128s-simple",
    "SPHINCS+-SHAKE-128f": "SPHINCS+-SHAKE-128f-simple",
    "SPHINCS+-SHAKE-192s": "SPHINCS+-SHAKE-192s-simple",
    "SPHINCS+-SHAKE-256s": "SPHINCS+-SHAKE-256s-simple",
}

_SIG_LIBOQS_NAMES.update(_LEGACY_SPHINCS_NAMES)


@functools.lru_cache(maxsize=1)
def _vendored_liboqs_dir() -> Path | None:
    """Return the bundled liboqs directory shipped inside our own wheel, if any.

    Populated at build time by hatch_build.py's LiboqsVendorBuildHook — only
    present in wheels built with QUANTUM_SAFE_VENDOR_LIBOQS=1 (our released
    wheels). A plain `pip install -e .` / sdist install has no such directory,
    and liboqs-python falls back to its normal system-lib-or-build-from-source
    behavior.

    The answer cannot change while the process runs, so it is computed once: this
    function is on the path of every KEM and signature call.
    """
    try:
        base = Path(str(importlib.resources.files("quantum_safe"))) / "_vendor" / "liboqs"
    except ModuleNotFoundError:
        return None
    return base if base.is_dir() else None


def _import_oqs() -> Any:  # noqa: ANN401
    """Import the oqs module or raise BackendNotAvailable.

    If we shipped a vendored liboqs binary and the caller hasn't already set
    OQS_INSTALL_PATH themselves, point liboqs-python at our bundled copy so it
    never attempts to download/compile liboqs from source.
    """
    if "OQS_INSTALL_PATH" not in os.environ:
        vendor_dir = _vendored_liboqs_dir()
        if vendor_dir is not None:
            os.environ["OQS_INSTALL_PATH"] = str(vendor_dir)

    try:
        import oqs

        return oqs
    except ImportError as exc:
        raise BackendNotAvailable("liboqs") from exc


def liboqs_versions() -> dict[str, Any]:
    """Report the loaded liboqs, the liboqs-python wrapping it, and whether they pair.

    ``paired`` is True when both have the same major.minor, which is what liboqs-python needs to
    load without its import-time warning, and what this release is built and tested with (see
    ``quantum_safe._liboqs_version``). Raises ``BackendNotAvailable`` if liboqs-python is not
    installed.
    """
    oqs = _import_oqs()
    liboqs_version = str(oqs.oqs_version())
    python_version = str(oqs.oqs_python_version())

    def _mm(v: str) -> tuple[str, ...]:
        return tuple(v.split(".")[:2])

    return {
        "liboqs": liboqs_version,
        "liboqs_python": python_version,
        "expected": LIBOQS_VERSION,
        "paired": _mm(liboqs_version) == _mm(python_version),
    }


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
        for canonical, candidates in _KEM_LIBOQS_NAMES.items():
            if any(c in enabled for c in candidates):
                info = _KEM_ALGORITHM_INFO.get(canonical)
                if info:
                    result.append(info)

        return result

    def _liboqs_name(self, algorithm: str) -> str:
        """Map a canonical name to the mechanism name the loaded liboqs build enables.

        Raises ``UnsupportedAlgorithm`` if the name is unknown or no candidate is enabled.
        """
        candidates = _KEM_LIBOQS_NAMES.get(algorithm)
        if candidates is None:
            raise UnsupportedAlgorithm(
                algorithm,
                available=list(_KEM_LIBOQS_NAMES.keys()),
            )
        enabled = set(_import_oqs().get_enabled_kem_mechanisms())
        for candidate in candidates:
            if candidate in enabled:
                return candidate
        # Known to the registry but not compiled into this liboqs: say what the build does offer.
        raise UnsupportedAlgorithm(
            algorithm,
            available=[a.name for a in self.supported_algorithms()],
        )

    def keygen(self, algorithm: str) -> tuple[bytes, bytes]:
        """Generate an ML-KEM (or other KEM) key pair.

        Returns (public_key_bytes, secret_key_bytes).

        Args:
            algorithm: Canonical algorithm name, e.g. "ML-KEM-768".

        Returns:
            (public_key_bytes, secret_key_bytes). The secret key is liboqs's expanded form
            (2400 bytes for ML-KEM-768).

        Raises:
            UnsupportedAlgorithm: if the name is unknown or the liboqs build does not enable it.
            KeyGenerationError: if liboqs fails to generate the key pair.
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

    def keygen_from_seed(self, algorithm: str, seed: bytes) -> tuple[bytes, bytes]:
        """Deterministic key generation from the FIPS 203 seed ``d || z`` (64 bytes).

        Returns (public_key_bytes, secret_key_bytes).

        Args:
            algorithm: Canonical algorithm name, e.g. "ML-KEM-768".
            seed: The 64-byte seed ``d || z``.

        Returns:
            (public_key_bytes, secret_key_bytes). The secret key is the expanded form.

        Raises:
            UnsupportedAlgorithm: if the name is unknown or not enabled, or the installed
                liboqs-python has no seeded key generation.
            KeyGenerationError: if liboqs rejects the seed or fails to generate the key pair.
        """
        oqs = _import_oqs()
        liboqs_name = self._liboqs_name(algorithm)
        try:
            kem = oqs.KeyEncapsulation(liboqs_name)
            pub = kem.generate_keypair_seed(bytes(seed))
            return bytes(pub), bytes(kem.export_secret_key())
        except AttributeError as exc:  # a liboqs-python without seeded generation
            raise UnsupportedAlgorithm(f"{algorithm} seeded key generation") from exc
        except Exception as exc:
            raise KeyGenerationError(
                f"liboqs seeded keygen failed for {algorithm}: {exc}", algorithm=algorithm
            ) from exc

    def encapsulate(self, algorithm: str, public_key: bytes) -> tuple[bytes, bytes]:
        """Encapsulate a shared secret under the given public key.

        Returns (ciphertext_bytes, shared_secret_bytes).

        Args:
            algorithm: Canonical algorithm name, e.g. "ML-KEM-768".
            public_key: The recipient's public key bytes.

        Returns:
            (ciphertext_bytes, shared_secret_bytes).

        Raises:
            UnsupportedAlgorithm: if the name is unknown or the liboqs build does not enable it.
            CryptoError: if liboqs fails to encapsulate.
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

    def decapsulate(self, algorithm: str, secret_key: bytes, ciphertext: bytes) -> bytes:
        """Decapsulate a shared secret from a ciphertext.

        Returns shared_secret_bytes.

        IMPORTANT: liboqs ML-KEM implements implicit rejection (per FIPS 203
        §6.3) — a malformed ciphertext returns a pseudorandom value rather
        than raising an exception. We check the output length to detect the
        most obvious failure modes, but we cannot distinguish a bad ciphertext
        from a good one by inspecting the output.

        A 64-byte seed key (``d || z``, made by the pyca backend) is decapsulated through
        the pyca backend.

        The local copy of the secret key is zeroed before the method returns.

        Args:
            algorithm: Canonical algorithm name, e.g. "ML-KEM-768".
            secret_key: The expanded secret key, or a 64-byte ML-KEM seed key.
            ciphertext: The ciphertext produced by encapsulation.

        Returns:
            The shared secret bytes (32 bytes for ML-KEM).

        Raises:
            DecapsulationError: if liboqs fails or returns a secret that is not 32 or 64 bytes.
            UnsupportedAlgorithm: if the name is unknown or the liboqs build does not enable it.
        """
        if algorithm.startswith("ML-KEM-") and len(secret_key) == 64:
            from quantum_safe.backends import get_kem_backend

            return get_kem_backend("pyca").decapsulate(algorithm, secret_key, ciphertext)
        oqs = _import_oqs()
        liboqs_name = self._liboqs_name(algorithm)

        # Use a mutable bytearray so we can zero the local copy after use.
        sk_buf = bytearray(secret_key)
        try:
            kem = oqs.KeyEncapsulation(liboqs_name, secret_key=bytes(sk_buf))
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
        finally:
            n = len(sk_buf)
            if n:
                ctypes.memset((ctypes.c_char * n).from_buffer(sk_buf), 0, n)

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
        """Return the signature algorithms this liboqs build enables, with their metadata.

        An algorithm is listed only if its liboqs mechanism is enabled in the installed build.
        """
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
        """Map a canonical name to its liboqs mechanism name.

        Raises ``UnsupportedAlgorithm`` if the name is not in the table; it does not check
        that the loaded build enables the mechanism.
        """
        name = _SIG_LIBOQS_NAMES.get(algorithm)
        if name is None:
            raise UnsupportedAlgorithm(
                algorithm,
                available=list(_SIG_LIBOQS_NAMES.keys()),
            )
        return name

    def keygen(self, algorithm: str) -> tuple[bytes, bytes]:
        """Generate a signing key pair.

        Args:
            algorithm: Canonical algorithm name, e.g. "ML-DSA-65".

        Returns:
            (public_key_bytes, secret_key_bytes). The secret key is liboqs's expanded form
            (4032 bytes for ML-DSA-65).

        Raises:
            UnsupportedAlgorithm: if the name is not one this backend knows.
            KeyGenerationError: if liboqs fails to generate the key pair, including when the
                build does not enable the mechanism.
        """
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

    @staticmethod
    def _seed_key(algorithm: str, secret_key: bytes) -> bool:
        """True for a 32-byte ML-DSA seed key (made by the pyca backend); liboqs cannot use it."""
        return algorithm.startswith("ML-DSA-") and len(secret_key) == 32

    def sign(
        self,
        algorithm: str,
        secret_key: bytes,
        message: bytes,
        context: bytes = b"",
    ) -> bytes:
        """Sign a message.

        A 32-byte seed key (made by the pyca backend) is signed through the pyca backend.

        Domain separation is done by a message prefix, not by FIPS 204's
        native context. This backend signs, with plain ML-DSA and an
        **empty** FIPS 204 context string, the bytes::

            context_len (1 byte) || context || message

        This is neither FIPS 204's native context (the ``ctx`` input of
        ML-DSA.Sign, §5.2) nor HashML-DSA (§5.4); a verifier that passes the
        context natively will not accept these signatures. Moving to the
        native context would change what is signed, so it would be a new,
        separately identified signature format, not a silent switch.

        The local copy of the secret key is zeroed before the method returns.

        Args:
            algorithm: Canonical algorithm name, e.g. "ML-DSA-65".
            secret_key: The expanded secret key, or a 32-byte ML-DSA seed key.
            message: The message to sign.
            context: Domain-separation context, at most 255 bytes.

        Returns:
            The signature bytes.

        Raises:
            ValueError: if ``context`` is longer than 255 bytes.
            UnsupportedAlgorithm: if the name is not one this backend knows.
            CryptoError: if liboqs fails to sign.
        """
        if self._seed_key(algorithm, secret_key):
            from quantum_safe.backends import get_signature_backend

            return get_signature_backend("pyca").sign(algorithm, secret_key, message, context)
        oqs = _import_oqs()
        liboqs_name = self._liboqs_name(algorithm)

        if len(context) > 255:
            raise ValueError(f"context must be <=255 bytes, got {len(context)}")

        # Prepend context using length-prefixed format
        msg_with_context = bytes([len(context)]) + context + message

        # Use a mutable bytearray so we can zero the local copy after use.
        sk_buf = bytearray(secret_key)
        try:
            sig_obj = oqs.Signature(liboqs_name, secret_key=bytes(sk_buf))
            signature = sig_obj.sign(msg_with_context)
            return bytes(signature)
        except Exception as exc:
            from quantum_safe.exceptions import CryptoError

            raise CryptoError(
                f"liboqs signing failed for {algorithm}: {exc}",
                algorithm=algorithm,
            ) from exc
        finally:
            n = len(sk_buf)
            if n:
                ctypes.memset((ctypes.c_char * n).from_buffer(sk_buf), 0, n)

    def verify(
        self,
        algorithm: str,
        public_key: bytes,
        message: bytes,
        signature: bytes,
        context: bytes = b"",
    ) -> bool:
        """Verify a signature. Returns True if valid, False if not.

        The message is verified under the same ``context_len || context || message`` prefix
        that :meth:`sign` produces.

        Args:
            algorithm: Canonical algorithm name, e.g. "ML-DSA-65".
            public_key: The signer's public key bytes.
            message: The signed message.
            signature: The signature bytes.
            context: Must match the context used when signing. A context longer than 255 bytes
                returns False.

        Returns:
            True if the signature is valid. False for an invalid signature or when liboqs
            raises while verifying.

        Raises:
            UnsupportedAlgorithm: if the name is not one this backend knows.
        """
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

    def sign_native_context(
        self,
        algorithm: str,
        secret_key: bytes,
        message: bytes,
        context: bytes,
    ) -> bytes:
        """ML-DSA.Sign with FIPS 204's native context (liboqs ``sign_with_ctx_str``).

        A 32-byte seed key is signed through the pyca backend. The local copy of the secret key
        is zeroed before the method returns.

        Args:
            algorithm: Canonical algorithm name, e.g. "ML-DSA-65".
            secret_key: The expanded secret key, or a 32-byte ML-DSA seed key.
            message: The message to sign, passed to liboqs unchanged.
            context: The FIPS 204 context string, at most 255 bytes.

        Returns:
            The signature bytes.

        Raises:
            ValueError: if ``context`` is longer than 255 bytes.
            UnsupportedAlgorithm: if the name is not one this backend knows.
            CryptoError: if liboqs fails to sign.
        """
        from quantum_safe.exceptions import CryptoError

        if self._seed_key(algorithm, secret_key):
            from quantum_safe.backends import get_signature_backend

            return get_signature_backend("pyca").sign_native_context(
                algorithm, secret_key, message, context
            )
        oqs = _import_oqs()
        liboqs_name = self._liboqs_name(algorithm)
        if len(context) > 255:
            raise ValueError(f"context must be <=255 bytes, got {len(context)}")
        sk_buf = bytearray(secret_key)
        try:
            sig_obj = oqs.Signature(liboqs_name, secret_key=bytes(sk_buf))
            return bytes(sig_obj.sign_with_ctx_str(message, context))
        except Exception as exc:
            raise CryptoError(
                f"liboqs native-context signing failed for {algorithm}: {exc}",
                algorithm=algorithm,
            ) from exc
        finally:
            n = len(sk_buf)
            if n:
                ctypes.memset((ctypes.c_char * n).from_buffer(sk_buf), 0, n)

    def verify_native_context(
        self,
        algorithm: str,
        public_key: bytes,
        message: bytes,
        signature: bytes,
        context: bytes,
    ) -> bool:
        """Verify a signature made with :meth:`sign_native_context` (``verify_with_ctx_str``).

        Args:
            algorithm: Canonical algorithm name, e.g. "ML-DSA-65".
            public_key: The signer's public key bytes.
            message: The signed message.
            signature: The signature bytes.
            context: The FIPS 204 context string used when signing. A context longer than
                255 bytes returns False.

        Returns:
            True if the signature is valid. False for an invalid signature or when liboqs
            raises while verifying.

        Raises:
            UnsupportedAlgorithm: if the name is not one this backend knows.
        """
        oqs = _import_oqs()
        liboqs_name = self._liboqs_name(algorithm)
        if len(context) > 255:
            return False
        try:
            sig_obj = oqs.Signature(liboqs_name)
            return bool(sig_obj.verify_with_ctx_str(message, signature, context, public_key))
        except Exception:  # noqa: BLE001
            return False

    def is_available(self) -> bool:
        """Return True if liboqs is importable and has ML-DSA-65 enabled."""
        try:
            oqs = _import_oqs()
            enabled = oqs.get_enabled_sig_mechanisms()
            return "ML-DSA-65" in enabled
        except Exception:  # noqa: BLE001
            return False
