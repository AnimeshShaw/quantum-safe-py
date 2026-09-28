"""
LMS stateful hash-based signatures (RFC 8554 / NIST SP 800-208).

CNSA 2.0 requires LMS or XMSS for software and firmware signing, and neither is
available through liboqs. This module provides LMS by wrapping ``pyhsslms``,
which is written by Russ Housley, a co-author of RFC 8554. It is an optional
dependency: import this module only if you need stateful signatures.

Read this before using it
-------------------------
LMS is **stateful**, and that word is doing more work than it usually does. Each
signature consumes a one-time key at index ``q``, and the private key advances.
Signing twice at the same index does not produce a warning or a wrong answer --
it produces two signatures that both verify, from which an attacker can forge
further signatures. The entire tree is then compromised, including every
signature already issued under it.

The failure is easy to reach by accident and impossible to detect afterwards
from the signatures alone:

* restore a VM snapshot, a database backup, or a container image
* copy a key file to a second signer
* crash after signing but before persisting the advanced index
* run two processes against the same key material

We measured the first case directly against ``pyhsslms``: deserialising a
snapshot rewinds ``q``, and two different messages signed at the rewound index
both verify.

What this wrapper does about it
-------------------------------
It refuses to make the unsafe thing convenient.

1. **Write-ahead index reservation.** The advanced index is persisted through
   the caller's state store *before* the signature is produced. Crashing between
   the two loses one unused index, which is harmless. The reverse order -- sign,
   then persist -- is what loses the key, so it is not offered.
2. **Rewind detection.** The store records a high-water mark. A key presented at
   an index at or below a mark already issued is refused rather than signed with.
   This converts the catastrophic silent case into a loud failure.
3. **Exhaustion is an error, not a wrap-around.** A key with no indices left
   raises instead of reusing.
4. **No in-process default store.** A caller must supply persistence, because a
   default that kept state in memory would be exactly the footgun this module
   exists to remove.

None of this makes LMS safe to use casually. It makes the dangerous paths
explicit. If a single key might ever be reachable from two places at once, LMS
is the wrong tool and a stateless scheme (ML-DSA, SLH-DSA) is the right one.

SP 800-208 scope
----------------
SP 800-208 approves LMS and XMSS, and also imposes requirements on key
generation and state management that a library cannot satisfy alone -- notably
that key generation happen inside a validated cryptographic module. Using this
module does not make a deployment SP 800-208 compliant; it provides the
algorithm and the state discipline the caller still has to operate correctly.
"""

from __future__ import annotations

from dataclasses import dataclass
from types import ModuleType
from typing import Protocol, cast, runtime_checkable

from quantum_safe.exceptions import QuantumSafeError


class StatefulSignatureError(QuantumSafeError):
    """Base class for LMS state-handling failures."""


class KeyExhaustedError(StatefulSignatureError):
    """Every one-time key in the tree has been used."""


class IndexReuseError(StatefulSignatureError):
    """The key was presented at an index that has already been issued.

    Raised when a key appears to have been rewound -- restored from a backup or
    snapshot, or copied to a second signer. Signing here would reuse a one-time
    key and compromise the tree, so it is refused.
    """


class StatePersistenceError(StatefulSignatureError):
    """The advanced index could not be persisted, so no signature was produced.

    Deliberately fatal. Continuing would mean issuing a signature whose index
    was never recorded, which is how the next restart reuses it.
    """


class _LmsPublicKeyLike(Protocol):
    """The subset of pyhsslms' LmsPublicKey this module relies on."""

    def serialize(self) -> bytes: ...


class _LmsPrivateKeyLike(Protocol):
    """The subset of pyhsslms' LmsPrivateKey this module relies on.

    Declared explicitly rather than typed as Any so that the coupling to the
    third-party object is visible and checkable.
    """

    q: int

    def sign(self, message: bytes) -> bytes: ...

    def serialize(self) -> bytes: ...

    def publicKey(self) -> _LmsPublicKeyLike: ...  # noqa: N802 - upstream spelling

    def maxSignatures(self) -> int: ...  # noqa: N802 - upstream spelling


@runtime_checkable
class LmsStateStore(Protocol):
    """Durable record of which indices a key has already issued.

    An implementation must be durable against process death and must not be
    shared by two signers without external mutual exclusion. A store backed by a
    transactional database, or by an fsync'd file with a lock, is appropriate;
    one backed by a dictionary is not, outside tests.
    """

    def high_water_mark(self, key_id: str) -> int:
        """Return the lowest index not yet issued for ``key_id`` (0 if unknown)."""
        ...

    def reserve(self, key_id: str, next_index: int) -> None:
        """Durably record that indices below ``next_index`` are spent.

        Must not return until the record survives process death. Raise to abort
        the signature.
        """
        ...


@dataclass(frozen=True)
class LmsKeyInfo:
    """Capacity and usage of an LMS key."""

    key_id: str
    max_signatures: int
    used: int

    @property
    def remaining(self) -> int:
        return self.max_signatures - self.used

    @property
    def exhausted(self) -> bool:
        return self.remaining <= 0


class InMemoryLmsStateStore:
    """Non-durable store, for tests only.

    Kept deliberately unusable in production: it forgets everything on exit, so
    a restart would rewind every key it tracked. It exists so the signing path
    can be tested without a database, and it says so in its name.
    """

    def __init__(self) -> None:
        self._marks: dict[str, int] = {}

    def high_water_mark(self, key_id: str) -> int:
        return self._marks.get(key_id, 0)

    def reserve(self, key_id: str, next_index: int) -> None:
        current = self._marks.get(key_id, 0)
        if next_index <= current:
            raise StatePersistenceError(
                f"refusing to move the high-water mark for {key_id!r} backwards: "
                f"{current} -> {next_index}"
            )
        self._marks[key_id] = next_index


def _require_pyhsslms() -> ModuleType:
    try:
        import pyhsslms
    except ImportError as exc:  # pragma: no cover - depends on environment
        raise StatefulSignatureError(
            "LMS support requires the optional 'pyhsslms' dependency. "
            "Install it with: pip install 'quantum-safe-py[lms]'"
        ) from exc
    return cast(ModuleType, pyhsslms)


class LmsSigner:
    """LMS signer that reserves each index durably before signing.

    Example:
        >>> store = MyDatabaseStateStore()          # doctest: +SKIP
        >>> signer = LmsSigner.generate("fw-signing-key-2027", store)  # doctest: +SKIP
        >>> sig = signer.sign(firmware_image)        # doctest: +SKIP

    The ``key_id`` is the identity the state store tracks. Two signers sharing a
    ``key_id`` must never run concurrently; the store is what serialises them,
    and an in-memory store cannot.
    """

    def __init__(self, key_id: str, private_key: _LmsPrivateKeyLike, store: LmsStateStore) -> None:
        self._key_id = key_id
        self._sk = private_key
        self._store = store
        self._verify_not_rewound()

    @classmethod
    def generate(
        cls,
        key_id: str,
        store: LmsStateStore,
        *,
        tree_height: int = 10,
        winternitz: int = 8,
    ) -> LmsSigner:
        """Generate a fresh LMS key.

        Args:
            key_id: identity under which the store tracks spent indices.
            store: durable state store.
            tree_height: 5, 10, 15, 20 or 25. Capacity is ``2**tree_height``
                signatures *for the lifetime of the key*, and the key cannot be
                extended afterwards, so size it for the whole deployment.
            winternitz: Winternitz parameter (1, 2, 4 or 8). Larger means smaller
                signatures and slower signing.
        """
        pyhsslms = _require_pyhsslms()
        try:
            lms_type = getattr(pyhsslms, f"lms_sha256_m32_h{tree_height}")
            lmots_type = getattr(pyhsslms, f"lmots_sha256_n32_w{winternitz}")
        except AttributeError as exc:
            raise ValueError(
                f"unsupported LMS parameters: tree_height={tree_height}, winternitz={winternitz}"
            ) from exc
        sk = pyhsslms.LmsPrivateKey(lms_type=lms_type, lmots_type=lmots_type)
        return cls(key_id, sk, store)

    @classmethod
    def load(cls, key_id: str, serialised_key: bytes, store: LmsStateStore) -> LmsSigner:
        """Load a serialised LMS private key.

        The rewind check runs during construction, so a key restored from a stale
        backup raises :class:`IndexReuseError` here rather than silently signing
        at an index that has already been issued.
        """
        pyhsslms = _require_pyhsslms()
        sk = pyhsslms.LmsPrivateKey.deserialize(serialised_key)
        return cls(key_id, sk, store)

    def _verify_not_rewound(self) -> None:
        mark = self._store.high_water_mark(self._key_id)
        current = int(self._sk.q)
        if current < mark:
            raise IndexReuseError(
                f"key {self._key_id!r} is at index {current} but index {mark} has "
                f"already been issued. This key has been rewound -- restored from a "
                f"backup or snapshot, or copied from another signer. Signing would "
                f"reuse a one-time key and compromise every signature made under "
                f"this key. Generate a new key instead."
            )

    @property
    def key_info(self) -> LmsKeyInfo:
        return LmsKeyInfo(
            key_id=self._key_id,
            max_signatures=int(self._sk.maxSignatures()),
            used=int(self._sk.q),
        )

    def public_key(self) -> bytes:
        return bytes(self._sk.publicKey().serialize())

    def serialize(self) -> bytes:
        """Serialise the private key.

        The result is only safe to restore if the state store is consulted on
        load, which :meth:`load` does. Restoring it by any other route rewinds
        the index.
        """
        return bytes(self._sk.serialize())

    def sign(self, message: bytes) -> bytes:
        """Sign ``message``, reserving the index durably first.

        Raises:
            KeyExhaustedError: no indices remain.
            IndexReuseError: the key has been rewound.
            StatePersistenceError: the index could not be recorded, so nothing
                was signed.
        """
        info = self.key_info
        if info.exhausted:
            raise KeyExhaustedError(
                f"key {self._key_id!r} has used all {info.max_signatures} of its "
                f"one-time keys. An LMS key cannot be extended; generate a new key "
                f"and distribute its public key."
            )
        self._verify_not_rewound()

        # Write-ahead: record that this index is spent before producing the
        # signature. Dying here costs one unused index. Doing it the other way
        # round costs the key.
        current_index = int(self._sk.q)
        try:
            self._store.reserve(self._key_id, current_index + 1)
        except StatefulSignatureError:
            raise
        except Exception as exc:
            raise StatePersistenceError(
                f"could not reserve index {current_index + 1} for key "
                f"{self._key_id!r}; no signature was produced"
            ) from exc

        return bytes(self._sk.sign(message))


def verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
    """Verify an LMS signature.

    Verification is stateless and carries none of the hazards above.
    """
    pyhsslms = _require_pyhsslms()
    try:
        pk = pyhsslms.LmsPublicKey.deserialize(public_key)
        return bool(pk.verify(message, signature))
    except Exception:
        return False
