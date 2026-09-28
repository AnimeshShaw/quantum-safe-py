"""Tests for LMS stateful signatures, concentrating on the state hazards.

The algorithm is the easy part. These tests are mostly about whether the wrapper
refuses to reuse a one-time key, because that is the failure that loses the key
rather than merely producing a wrong answer.
"""

from __future__ import annotations

import pytest

from quantum_safe.signatures.stateful import (
    IndexReuseError,
    InMemoryLmsStateStore,
    KeyExhaustedError,
    LmsSigner,
    StatePersistenceError,
    verify,
)

pyhsslms = pytest.importorskip("pyhsslms", reason="LMS needs the optional [lms] extra")

# h5 is the smallest tree: 32 signatures, fast enough to exhaust in a test.
SMALL_TREE = 5


@pytest.fixture
def store() -> InMemoryLmsStateStore:
    return InMemoryLmsStateStore()


@pytest.fixture
def signer(store: InMemoryLmsStateStore) -> LmsSigner:
    return LmsSigner.generate("test-key", store, tree_height=SMALL_TREE)


class TestSigningAndVerifying:
    def test_round_trip(self, signer: LmsSigner) -> None:
        msg = b"firmware image v1"
        sig = signer.sign(msg)
        assert verify(signer.public_key(), msg, sig)

    def test_rejects_tampered_message(self, signer: LmsSigner) -> None:
        sig = signer.sign(b"original")
        assert not verify(signer.public_key(), b"tampered", sig)

    def test_each_signature_consumes_one_index(self, signer: LmsSigner) -> None:
        assert signer.key_info.used == 0
        assert signer.key_info.remaining == 2**SMALL_TREE
        signer.sign(b"a")
        signer.sign(b"b")
        assert signer.key_info.used == 2
        assert signer.key_info.remaining == 2**SMALL_TREE - 2

    def test_verification_needs_no_state(self, signer: LmsSigner) -> None:
        """Verifiers carry none of the signer's hazards."""
        msg = b"payload"
        sig = signer.sign(msg)
        pk = signer.public_key()
        assert verify(pk, msg, sig)
        assert verify(pk, msg, sig)  # repeatable, unlike signing


class TestExhaustion:
    def test_raises_rather_than_wrapping_around(self, store: InMemoryLmsStateStore) -> None:
        """A spent key must fail loudly, never reuse index 0."""
        signer = LmsSigner.generate("small", store, tree_height=SMALL_TREE)
        for i in range(2**SMALL_TREE):
            signer.sign(f"msg-{i}".encode())
        assert signer.key_info.exhausted
        with pytest.raises(KeyExhaustedError, match="cannot be extended"):
            signer.sign(b"one too many")


class TestRewindDetection:
    """The case that loses the key: a restored backup re-signing at a spent index."""

    def test_reload_from_stale_snapshot_is_refused(self, store: InMemoryLmsStateStore) -> None:
        signer = LmsSigner.generate("prod-key", store, tree_height=SMALL_TREE)
        signer.sign(b"first")
        snapshot = signer.serialize()  # backup taken here
        signer.sign(b"second")  # key advances past the snapshot
        signer.sign(b"third")

        # Restoring the snapshot rewinds the index. Without the guard this signs
        # at an index already issued, which is the fatal case.
        with pytest.raises(IndexReuseError, match="rewound"):
            LmsSigner.load("prod-key", snapshot, store)

    def test_error_explains_the_consequence_not_just_the_condition(
        self, store: InMemoryLmsStateStore
    ) -> None:
        signer = LmsSigner.generate("prod-key", store, tree_height=SMALL_TREE)
        signer.sign(b"first")
        snapshot = signer.serialize()
        signer.sign(b"second")

        with pytest.raises(IndexReuseError) as exc:
            LmsSigner.load("prod-key", snapshot, store)
        message = str(exc.value)
        assert "compromise" in message
        assert "Generate a new key" in message

    def test_reload_at_the_current_index_is_allowed(self, store: InMemoryLmsStateStore) -> None:
        """A snapshot that is up to date is a legitimate restore."""
        signer = LmsSigner.generate("prod-key", store, tree_height=SMALL_TREE)
        signer.sign(b"first")
        current = signer.serialize()
        reloaded = LmsSigner.load("prod-key", current, store)
        assert reloaded.sign(b"second")


class TestWriteAheadReservation:
    def test_no_signature_is_released_if_the_index_cannot_be_recorded(
        self,
    ) -> None:
        """Persistence failure must abort the signature, not proceed past it.

        Signing first and recording afterwards is what reuses an index across a
        crash, so a store failure has to be fatal.
        """

        class FailingStore:
            def high_water_mark(self, key_id: str) -> int:
                return 0

            def reserve(self, key_id: str, next_index: int) -> None:
                raise OSError("disk full")

        signer = LmsSigner.generate("k", FailingStore(), tree_height=SMALL_TREE)
        with pytest.raises(StatePersistenceError, match="no signature was produced"):
            signer.sign(b"payload")

    def test_index_is_reserved_before_the_signature_exists(
        self, store: InMemoryLmsStateStore
    ) -> None:
        """The mark must already be advanced by the time signing happens."""
        observed: list[int] = []

        class ObservingStore(InMemoryLmsStateStore):
            def reserve(self, key_id: str, next_index: int) -> None:
                observed.append(next_index)
                super().reserve(key_id, next_index)

        signer = LmsSigner.generate("k", ObservingStore(), tree_height=SMALL_TREE)
        signer.sign(b"payload")
        assert observed == [1], "expected index 1 to be reserved before signing at 0"

    def test_store_refuses_to_move_the_mark_backwards(self, store: InMemoryLmsStateStore) -> None:
        store.reserve("k", 5)
        with pytest.raises(StatePersistenceError, match="backwards"):
            store.reserve("k", 3)


class TestOptionalDependencyContract:
    def test_in_memory_store_is_named_to_discourage_production_use(self) -> None:
        """The only bundled store says in its name that it is not durable."""
        assert "InMemory" in InMemoryLmsStateStore.__name__
        assert "test" in (InMemoryLmsStateStore.__doc__ or "").lower()

    def test_module_documents_the_sp_800_208_scope_limit(self) -> None:
        """Providing the algorithm is not the same as being SP 800-208 compliant."""
        import quantum_safe.signatures.stateful as mod

        doc = mod.__doc__ or ""
        assert "SP 800-208" in doc
        assert "does not make a deployment SP 800-208 compliant" in doc
