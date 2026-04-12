"""
quantum_safe.migrate.upgrader
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Key upgrader: takes an existing classical key and produces a hybrid
replacement that retains backward compatibility.

The central design challenge in key migration is that you can't just
swap keys atomically — at some point during rollout, both old and new
clients exist. The Upgrader solves this by producing a HybridKey that:

  1. Contains the original classical sub-key unchanged.
  2. Adds a PQC sub-key alongside it.
  3. Sets migration_state=HYBRID_TRANSITION so the state machine
     can track progress.

This means:
  - Old senders using X25519-only can still encrypt to the new public key
    (they just use the X25519 component and ignore the ML-KEM extension).
  - New senders using HybridKEM use both components.
  - The upgrade is reversible during the transition period.

Supported upgrade paths
------------------------
  X25519 private key     → X25519+ML-KEM-768 hybrid KEM key
  Ed25519 signing key    → Ed25519+ML-DSA-65 hybrid signing key
  ECDSA P-256 sign key   → P-256+ML-DSA-65 hybrid signing key
  (pure PQC keys are already migrated — no upgrade needed)

Upgrade result
--------------
UpgradeResult bundles the new hybrid KeyPair with metadata about what
was done. The original key bytes are NOT stored in the result — the
caller should keep the original for the backward-compat window and
then delete it after the migration period.
"""

from __future__ import annotations

import warnings
from dataclasses import dataclass
from typing import Any

from quantum_safe.types import KeyPair, MigrationState, PublicKey, SecretKey


@dataclass
class UpgradeResult:
    """Result of a key upgrade operation.

    Attributes:
        new_keypair:        The upgraded hybrid keypair.
        old_algorithm:      Algorithm string of the key before upgrade.
        new_algorithm:      Algorithm string of the upgraded key.
        migration_state:    Migration state of the new key (always HYBRID_TRANSITION).
        backward_compat:    True if the new key is backward-compatible with
                            the old algorithm (i.e. old clients can still use it).
        notes:              Human-readable notes about the upgrade.
    """

    new_keypair: KeyPair
    old_algorithm: str
    new_algorithm: str
    migration_state: MigrationState
    backward_compat: bool
    notes: str = ""

    def __repr__(self) -> str:
        return (
            f"UpgradeResult("
            f"{self.old_algorithm!r} → {self.new_algorithm!r}, "
            f"compat={self.backward_compat})"
        )


class Upgrader:
    """Upgrades classical keys to hybrid PQC keys.

    All methods are class methods — no instantiation needed.

    Example::

        from quantum_safe.migrate import Upgrader
        from quantum_safe.types.keys import MigrationState

        # Upgrade an X25519 secret key to hybrid
        result = Upgrader.upgrade_kem_key(
            classical_secret_bytes=x25519_private_bytes,
            classical_public_bytes=x25519_public_bytes,
            classical_algorithm="X25519",
            target_pqc="ML-KEM-768",
            backend="auto",
        )
        new_kp = result.new_keypair
        print(new_kp.algorithm)  # "X25519+ML-KEM-768"
    """

    @classmethod
    def upgrade_kem_key(
        cls,
        classical_secret_bytes: bytes,
        classical_public_bytes: bytes,
        classical_algorithm: str = "X25519",
        target_pqc: str = "ML-KEM-768",
        backend: str = "auto",
    ) -> UpgradeResult:
        """Upgrade a classical KEM key to a hybrid key.

        The original classical sub-key is retained in the output — it is
        the same bytes as classical_secret_bytes / classical_public_bytes,
        just wrapped alongside the new PQC component.

        Args:
            classical_secret_bytes: Raw bytes of the classical private key.
                                    For X25519: 32 bytes.
            classical_public_bytes: Raw bytes of the classical public key.
                                    For X25519: 32 bytes.
            classical_algorithm:    "X25519" or "P-256".
            target_pqc:             PQC algorithm to add. Default "ML-KEM-768".
            backend:                PQC backend.

        Returns:
            UpgradeResult with the new hybrid KeyPair.
        """
        from quantum_safe.backends import get_kem_backend
        from quantum_safe.kem.algorithms import canonical_hybrid_name, validate_hybrid_combination
        from quantum_safe.kem.hybrid import _pack_components

        validate_hybrid_combination(classical_algorithm, target_pqc)
        new_algo = canonical_hybrid_name(classical_algorithm, target_pqc)

        # Generate a fresh PQC sub-key
        pqc_backend = get_kem_backend(backend)
        pqc_pub_bytes, pqc_sec_bytes = pqc_backend.keygen(target_pqc)

        # Pack: classical first, PQC second (same format as HybridKEM.generate_keypair)
        combined_pub = _pack_components(classical_public_bytes, pqc_pub_bytes)
        combined_sec = _pack_components(classical_secret_bytes, pqc_sec_bytes)

        new_pub = PublicKey(
            raw=combined_pub,
            algorithm=new_algo,
            migration_state=MigrationState.HYBRID_TRANSITION,
            backend_tag=pqc_backend.name,
        )
        new_sec = SecretKey(
            raw=combined_sec,
            algorithm=new_algo,
            migration_state=MigrationState.HYBRID_TRANSITION,
            backend_tag=pqc_backend.name,
        )
        new_kp = KeyPair(public=new_pub, secret=new_sec)

        return UpgradeResult(
            new_keypair=new_kp,
            old_algorithm=classical_algorithm,
            new_algorithm=new_algo,
            migration_state=MigrationState.HYBRID_TRANSITION,
            backward_compat=True,
            notes=(
                f"Original {classical_algorithm} sub-key retained in hybrid key. "
                f"Old senders can still use the {classical_algorithm} component. "
                f"New senders will use the full {new_algo} hybrid construction."
            ),
        )

    @classmethod
    def upgrade_signing_key(
        cls,
        classical_secret_bytes: bytes,
        classical_public_bytes: bytes,
        classical_algorithm: str = "Ed25519",
        target_pqc: str = "ML-DSA-65",
        backend: str = "auto",
    ) -> UpgradeResult:
        """Upgrade a classical signing key to a hybrid signing key.

        Args:
            classical_secret_bytes: Raw bytes of the classical private key.
                                    For Ed25519: 32 bytes.
            classical_public_bytes: Raw bytes of the classical public key.
                                    For Ed25519: 32 bytes.
            classical_algorithm:    "Ed25519" or "P-256".
            target_pqc:             PQC signature algorithm. Default "ML-DSA-65".
            backend:                PQC backend.

        Returns:
            UpgradeResult with the new hybrid signing KeyPair.
        """
        from quantum_safe.backends import get_signature_backend
        from quantum_safe.signatures.algorithms import (
            canonical_hybrid_name,
            validate_hybrid_combination,
        )
        from quantum_safe.signatures.hybrid import _pack_components

        validate_hybrid_combination(classical_algorithm, target_pqc)
        new_algo = canonical_hybrid_name(classical_algorithm, target_pqc)

        # Generate a fresh PQC signing sub-key
        sig_backend = get_signature_backend(backend)
        pqc_pub_bytes, pqc_sec_bytes = sig_backend.keygen(target_pqc)

        # Pack: classical first, PQC second
        combined_pub = _pack_components(classical_public_bytes, pqc_pub_bytes)
        combined_sec = _pack_components(classical_secret_bytes, pqc_sec_bytes)

        new_pub = PublicKey(
            raw=combined_pub,
            algorithm=new_algo,
            migration_state=MigrationState.HYBRID_TRANSITION,
            backend_tag=sig_backend.name,
        )
        new_sec = SecretKey(
            raw=combined_sec,
            algorithm=new_algo,
            migration_state=MigrationState.HYBRID_TRANSITION,
            backend_tag=sig_backend.name,
        )
        new_kp = KeyPair(public=new_pub, secret=new_sec)

        return UpgradeResult(
            new_keypair=new_kp,
            old_algorithm=classical_algorithm,
            new_algorithm=new_algo,
            migration_state=MigrationState.HYBRID_TRANSITION,
            backward_compat=True,
            notes=(
                f"Original {classical_algorithm} signing key retained. "
                f"Existing verifiers can still check the {classical_algorithm} sub-signature. "
                f"New verifiers require both sub-signatures to pass."
            ),
        )

    @classmethod
    def strip_classical_component(cls, hybrid_keypair: KeyPair) -> KeyPair:
        """Remove the classical sub-key from a hybrid keypair.

        Use this when you're confident all clients support PQC and you
        want to move to PQC_ONLY migration state.

        Warning: This is a one-way operation. Old clients that only
        support classical algorithms will no longer be able to use
        the returned key. Make sure you've fully migrated before calling this.

        Args:
            hybrid_keypair: A keypair in HYBRID_TRANSITION or PQC_PREFERRED state.

        Returns:
            A new KeyPair with only the PQC component, in PQC_ONLY state.

        Raises:
            ValueError: if the keypair is not in a hybrid state.
        """
        if "+" not in hybrid_keypair.algorithm:
            raise ValueError(
                f"Key '{hybrid_keypair.algorithm}' is not a hybrid key. "
                f"Nothing to strip."
            )

        from quantum_safe.exceptions import DecapsulationError
        from quantum_safe.kem.hybrid import _unpack_components

        # Determine if this is a KEM or signature key based on algorithm name
        algo = hybrid_keypair.algorithm
        _, pqc_algo = algo.split("+", 1)

        # Unpack the PQC-only components
        try:
            _classical_pub, pqc_pub = _unpack_components(hybrid_keypair.public.raw_bytes)
            _classical_sec, pqc_sec = _unpack_components(hybrid_keypair.secret.raw_bytes)
        except DecapsulationError as exc:
            raise ValueError(f"Failed to unpack hybrid key: {exc}") from exc

        new_pub = PublicKey(
            raw=pqc_pub,
            algorithm=pqc_algo,
            migration_state=MigrationState.PQC_ONLY,
            backend_tag=hybrid_keypair.public.backend_tag,
        )
        new_sec = SecretKey(
            raw=pqc_sec,
            algorithm=pqc_algo,
            migration_state=MigrationState.PQC_ONLY,
            backend_tag=hybrid_keypair.secret.backend_tag,
        )

        warnings.warn(
            f"strip_classical_component() produced a PQC-only key '{pqc_algo}'. "
            f"Classical clients can no longer use this key. "
            f"This action should be logged in your migration audit trail.",
            stacklevel=2,
        )

        return KeyPair(public=new_pub, secret=new_sec)

    @classmethod
    def check_needs_upgrade(cls, keypair: KeyPair) -> bool:
        """Return True if the keypair should be upgraded.

        A key needs upgrade if it is in CLASSICAL_ONLY migration state.
        HYBRID_TRANSITION and above are considered "migrated enough" for
        the transition period.
        """
        state = keypair.public.migration_state
        return state == MigrationState.CLASSICAL_ONLY

    @classmethod
    def describe_key(cls, keypair: KeyPair) -> dict[str, Any]:
        """Return a human-readable description of a key's migration status.

        Useful for reporting tools and dashboards.
        """
        pub = keypair.public
        is_hybrid = "+" in keypair.algorithm

        return {
            "algorithm":        keypair.algorithm,
            "migration_state":  pub.migration_state.value,
            "is_hybrid":        is_hybrid,
            "needs_upgrade":    cls.check_needs_upgrade(keypair),
            "fingerprint":      pub.fingerprint()[:16] + "...",
            "public_key_size":  len(pub.raw_bytes),
            "recommendation":   cls._recommend(pub.migration_state, is_hybrid),
        }

    @staticmethod
    def _recommend(state: MigrationState, is_hybrid: bool) -> str:
        if state == MigrationState.CLASSICAL_ONLY:
            return (
                "Upgrade to HYBRID_TRANSITION using "
                "Upgrader.upgrade_kem_key() or upgrade_signing_key()"
            )
        if state == MigrationState.HYBRID_TRANSITION:
            return "Transition complete. Advance to PQC_PREFERRED when all clients support hybrid."
        if state == MigrationState.PQC_PREFERRED:
            return "Consider moving to PQC_ONLY once all classical clients are retired."
        if state == MigrationState.PQC_ONLY:
            return "Fully migrated. No action needed."
        return "Unknown state — inspect manually."
