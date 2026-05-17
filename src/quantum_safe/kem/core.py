"""
quantum_safe.kem.core
~~~~~~~~~~~~~~~~~~~~~

The KEM class: single-algorithm Key Encapsulation Mechanism.

Most users should use HybridKEM instead — it gives you classical + PQC
security without any extra work.  KEM is for when you specifically need
a single PQC algorithm, e.g.:

  - Benchmarking a specific algorithm
  - Protocol testing against a reference implementation
  - Cases where key size is critical and hybrid overhead matters

Usage::

    from quantum_safe import KEM

    kem = KEM("ML-KEM-768")
    kp  = kem.generate_keypair()
    ct, ss = kem.encapsulate(kp.public)
    ss2    = kem.decapsulate(kp.secret, ct)
    assert ss == ss2
"""

from __future__ import annotations

import warnings
from typing import TYPE_CHECKING

from quantum_safe.backends import get_kem_backend
from quantum_safe.exceptions import InsecureOperationError, UnsupportedAlgorithm
from quantum_safe.kem.algorithms import (
    MINIMUM_NIST_LEVEL,
    get_algorithm_spec,
)
from quantum_safe.types import (
    CipherText,
    KeyPair,
    MigrationState,
    PublicKey,
    SecretKey,
    SharedSecret,
)

if TYPE_CHECKING:
    from quantum_safe.backends.base import AbstractKEMBackend


class KEM:
    """Single-algorithm KEM.

    Wraps a backend and presents a typed, safe interface. Key decisions:

    - Key generation always returns a KeyPair (not raw bytes).
    - Encapsulate takes a PublicKey, returns (CipherText, SharedSecret).
    - Decapsulate takes (SecretKey, CipherText), returns SharedSecret.
    - All inputs/outputs are typed — you can't accidentally pass a
      shared secret where a ciphertext is expected.

    Args:
        algorithm:        PQC algorithm name. Defaults to ML-KEM-768.
        backend:          Backend name: "auto", "liboqs", "rustcrypto".
                          "auto" tries rustcrypto first, then liboqs.
        allow_low_security: If True, allows NIST level 1 algorithms without
                          warning. Default False (warns on L1).
        strict:           If True, raises instead of warning for non-standard
                          configurations. Default False.
    """

    def __init__(
        self,
        algorithm: str = "ML-KEM-768",
        backend: str = "auto",
        allow_low_security: bool = False,
        strict: bool = False,
    ) -> None:
        self._algorithm = algorithm
        self._strict = strict
        self._spec = get_algorithm_spec(algorithm)
        self._backend: AbstractKEMBackend = get_kem_backend(backend)

        # Security level check
        if self._spec.nist_level < MINIMUM_NIST_LEVEL:
            msg = (
                f"Algorithm '{algorithm}' is at NIST level {self._spec.nist_level}, "
                f"below the minimum recommended level {MINIMUM_NIST_LEVEL}."
            )
            if strict:
                raise InsecureOperationError(msg, algorithm=algorithm)
            warnings.warn(msg, stacklevel=2)

        if not self._spec.is_nist_standard:
            msg = (
                f"Algorithm '{algorithm}' is not a NIST standardized algorithm. "
                f"It may not be suitable for production use."
            )
            if strict:
                raise InsecureOperationError(msg, algorithm=algorithm)
            warnings.warn(msg, stacklevel=2)

    @property
    def algorithm(self) -> str:
        """The PQC algorithm name."""
        return self._algorithm

    @property
    def backend_name(self) -> str:
        """Name of the backend being used."""
        return self._backend.name

    def generate_keypair(self) -> KeyPair:
        """Generate a fresh key pair for this algorithm.

        Returns:
            KeyPair with .public (PublicKey) and .secret (SecretKey).

        Example::

            kp = kem.generate_keypair()
            print(kp.public.fingerprint())
        """
        pub_bytes, sec_bytes = self._backend.keygen(self._algorithm)

        pub = PublicKey(
            raw=pub_bytes,
            algorithm=self._algorithm,
            migration_state=MigrationState.PQC_ONLY,
            backend_tag=self._backend.name,
        )
        sec = SecretKey(
            raw=sec_bytes,
            algorithm=self._algorithm,
            migration_state=MigrationState.PQC_ONLY,
            backend_tag=self._backend.name,
        )
        return KeyPair(public=pub, secret=sec)

    def encapsulate(self, public_key: PublicKey) -> tuple[CipherText, SharedSecret]:
        """Encapsulate a shared secret under the recipient's public key.

        Args:
            public_key: The recipient's public key. Must be for the same
                        algorithm as this KEM instance.

        Returns:
            (ct, ss): CipherText to send to the recipient, SharedSecret
                      for the sender to use.

        Raises:
            UnsupportedAlgorithm: if the key's algorithm doesn't match.
        """
        if public_key.algorithm != self._algorithm:
            raise UnsupportedAlgorithm(
                public_key.algorithm,
                available=[self._algorithm],
            )

        ct_bytes, ss_bytes = self._backend.encapsulate(self._algorithm, public_key.raw_bytes)

        ct = CipherText(data=ct_bytes, algorithm=self._algorithm)
        # SS must be exactly 32 bytes for NIST-standard algorithms
        ss = SharedSecret(data=ss_bytes[:32], algorithm=self._algorithm, is_hybrid=False)
        return ct, ss

    def decapsulate(self, secret_key: SecretKey, ciphertext: CipherText) -> SharedSecret:
        """Decapsulate: recover the shared secret from a ciphertext.

        Args:
            secret_key: The recipient's secret key.
            ciphertext: The CipherText from the sender.

        Returns:
            SharedSecret matching the one the sender derived.

        Raises:
            DecapsulationError: if decapsulation fails. Note that ML-KEM
                implements implicit rejection (FIPS 203 §6.3), so malformed
                ciphertexts produce a pseudorandom value rather than raising.
                The error is raised only for structural failures.
        """
        if secret_key.algorithm != self._algorithm:
            raise UnsupportedAlgorithm(
                secret_key.algorithm,
                available=[self._algorithm],
            )

        ss_bytes = self._backend.decapsulate(
            self._algorithm, secret_key.raw_bytes, bytes(ciphertext)
        )
        return SharedSecret(data=ss_bytes[:32], algorithm=self._algorithm, is_hybrid=False)

    def __repr__(self) -> str:
        return f"KEM(algo={self._algorithm!r}, backend={self._backend.name!r})"
