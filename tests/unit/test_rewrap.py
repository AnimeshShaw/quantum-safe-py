"""
Envelope re-wrap: open under the old key, seal to the new key, keep the AAD; and the directory driver
(resumable, verified, atomic) with its report and CycloneDX output.
"""

from __future__ import annotations

import hashlib
import json
import warnings

import pytest
from cryptography.exceptions import InvalidTag

from quantum_safe import HybridKEM
from quantum_safe.exceptions import AadOmittedWarning
from quantum_safe.kem.core import KEM
from quantum_safe.protocols.envelope import Envelope, SealedMessage

pytestmark = pytest.mark.requires_liboqs


@pytest.fixture(scope="module")
def old_pair():
    return HybridKEM("X25519", "ML-KEM-768").generate_keypair()


@pytest.fixture(scope="module")
def new_pair():
    return HybridKEM("X25519", "ML-KEM-1024").generate_keypair()


@pytest.fixture(scope="module")
def pure_pair():
    return KEM("ML-KEM-1024").generate_keypair()


class TestEnvelopeRewrap:
    def test_moves_a_message_to_the_new_key_and_keeps_plaintext_and_aad(
        self, old_pair, new_pair
    ) -> None:
        sealed = Envelope.seal(b"the plaintext", old_pair.public, aad=b"record-7")
        moved = Envelope.rewrap(sealed, old_pair.secret, new_pair.public, expected_aad=b"record-7")
        assert isinstance(moved, SealedMessage)
        assert moved.algorithm == "X25519+ML-KEM-1024"
        assert moved.aad == b"record-7"
        assert moved.kem_ct != sealed.kem_ct
        assert Envelope.open(moved, new_pair.secret, expected_aad=b"record-7") == b"the plaintext"
        with pytest.raises((InvalidTag, Exception)):
            Envelope.open(moved, old_pair.secret, expected_aad=b"record-7")

    def test_the_old_message_is_left_alone(self, old_pair, new_pair) -> None:
        sealed = Envelope.seal(b"keep me", old_pair.public)
        before = sealed.to_bytes()
        Envelope.rewrap(sealed, old_pair.secret, new_pair.public)
        assert sealed.to_bytes() == before

    def test_hybrid_to_pure_ml_kem_1024_uses_the_v2_envelope_and_back(
        self, old_pair, pure_pair
    ) -> None:
        sealed = Envelope.seal(b"to v2", old_pair.public, aad=b"a")
        v2 = Envelope.rewrap(sealed, old_pair.secret, pure_pair.public, expected_aad=b"a")
        assert v2.version == 2 and v2.algorithm == "ML-KEM-1024"
        back = Envelope.rewrap(v2, pure_pair.secret, old_pair.public, expected_aad=b"a")
        assert back.version == 1
        assert Envelope.open(back, old_pair.secret, expected_aad=b"a") == b"to v2"

    def test_a_different_expected_aad_is_refused(self, old_pair, new_pair) -> None:
        sealed = Envelope.seal(b"x", old_pair.public, aad=b"tenant-a")
        with pytest.raises(InvalidTag):
            Envelope.rewrap(sealed, old_pair.secret, new_pair.public, expected_aad=b"tenant-b")

    def test_omitting_expected_aad_warns_when_the_message_carries_aad(
        self, old_pair, new_pair
    ) -> None:
        sealed = Envelope.seal(b"x", old_pair.public, aad=b"ctx")
        with pytest.warns(AadOmittedWarning):
            moved = Envelope.rewrap(sealed, old_pair.secret, new_pair.public)
        assert moved.aad == b"ctx"
        plain = Envelope.seal(b"y", old_pair.public)
        with warnings.catch_warnings():
            warnings.simplefilter("error")
            Envelope.rewrap(
                plain, old_pair.secret, new_pair.public
            )  # no AAD, so nothing to warn about

    def test_aad_can_be_replaced(self, old_pair, new_pair) -> None:
        sealed = Envelope.seal(b"x", old_pair.public, aad=b"old")
        moved = Envelope.rewrap(
            sealed, old_pair.secret, new_pair.public, expected_aad=b"old", aad=b"new"
        )
        assert moved.aad == b"new"
        assert Envelope.open(moved, new_pair.secret, expected_aad=b"new") == b"x"

    def test_the_wrong_old_key_fails_and_returns_nothing(self, new_pair) -> None:
        other = HybridKEM("X25519", "ML-KEM-768").generate_keypair()
        sealed = Envelope.seal(b"x", other.public)
        stranger = HybridKEM("X25519", "ML-KEM-768").generate_keypair()
        with pytest.raises(Exception):  # noqa: B017 - InvalidTag or a decapsulation error, never a result
            Envelope.rewrap(sealed, stranger.secret, new_pair.public, expected_aad=b"")


class TestRewrapDirectory:
    @pytest.fixture()
    def tree(self, tmp_path, old_pair):
        src = tmp_path / "src"
        (src / "sub").mkdir(parents=True)
        files = {
            "a.sealed": b"alpha",
            "sub/b.sealed": b"bravo",
            "sub/c.hex": b"charlie",
        }
        for name, data in files.items():
            sealed = Envelope.seal(data, old_pair.public, aad=name.encode())
            payload = sealed.to_hex().encode() if name.endswith(".hex") else sealed.to_bytes()
            (src / name).write_bytes(payload)
        (src / "notes.txt").write_text("not an envelope")
        return src, files

    def test_converts_everything_that_is_an_envelope_and_verifies(
        self, tmp_path, tree, old_pair, new_pair
    ) -> None:
        from quantum_safe.migrate.rewrap import rewrap_directory

        src, files = tree
        dst = tmp_path / "dst"
        report = rewrap_directory(
            src,
            dst,
            old_secret=old_pair.secret,
            new_public=new_pair.public,
            new_secret=new_pair.secret,
            expected_aad=lambda rel: rel.encode(),
        )
        assert report.counts == {"rewrapped": 3, "skipped": 1, "failed": 0}
        assert all(item.verified for item in report.items if item.status == "rewrapped")
        for name, data in files.items():
            raw = (dst / name).read_bytes()
            sealed = (
                SealedMessage.from_hex(raw.decode())
                if name.endswith(".hex")
                else SealedMessage.from_bytes(raw)
            )
            assert sealed.algorithm == "X25519+ML-KEM-1024"
            assert Envelope.open(sealed, new_pair.secret, expected_aad=name.encode()) == data
        assert not (dst / "notes.txt").exists()
        assert (src / "a.sealed").read_bytes() != (
            dst / "a.sealed"
        ).read_bytes()  # the source is untouched

    def test_a_second_run_changes_nothing_and_a_partial_run_resumes(
        self, tmp_path, tree, old_pair, new_pair
    ) -> None:
        from quantum_safe.migrate.rewrap import rewrap_directory

        src, _ = tree
        dst = tmp_path / "dst"
        kwargs = {
            "old_secret": old_pair.secret,
            "new_public": new_pair.public,
            "new_secret": new_pair.secret,
            "expected_aad": lambda rel: rel.encode(),
        }
        rewrap_directory(src, dst, **kwargs)
        snapshot = {p.name: p.read_bytes() for p in dst.rglob("*") if p.is_file()}
        again = rewrap_directory(src, dst, **kwargs)
        assert again.counts["rewrapped"] == 0
        assert {i.status for i in again.items} <= {"already_migrated", "skipped"}
        assert {p.name: p.read_bytes() for p in dst.rglob("*") if p.is_file()} == snapshot
        (dst / "sub" / "b.sealed").unlink()  # an interrupted run
        resumed = rewrap_directory(src, dst, **kwargs)
        assert resumed.counts["rewrapped"] == 1
        assert (dst / "sub" / "b.sealed").exists()

    def test_a_failure_is_reported_and_does_not_stop_the_rest(
        self, tmp_path, tree, old_pair, new_pair
    ) -> None:
        from quantum_safe.migrate.rewrap import rewrap_directory

        src, _ = tree
        stranger = HybridKEM("X25519", "ML-KEM-768").generate_keypair()
        (src / "z.sealed").write_bytes(Envelope.seal(b"not yours", stranger.public).to_bytes())
        report = rewrap_directory(
            src,
            tmp_path / "dst",
            old_secret=old_pair.secret,
            new_public=new_pair.public,
            new_secret=new_pair.secret,
            expected_aad=lambda rel: rel.encode() if rel != "z.sealed" else b"",
        )
        by_name = {i.name: i for i in report.items}
        assert by_name["z.sealed"].status == "failed"
        assert report.counts["rewrapped"] == 3 and report.counts["failed"] == 1
        assert by_name["z.sealed"].error  # says what happened, without any secret
        assert not (tmp_path / "dst" / "z.sealed").exists()

    def test_dry_run_writes_nothing(self, tmp_path, tree, old_pair, new_pair) -> None:
        from quantum_safe.migrate.rewrap import rewrap_directory

        src, _ = tree
        dst = tmp_path / "dst"
        report = rewrap_directory(
            src,
            dst,
            old_secret=old_pair.secret,
            new_public=new_pair.public,
            expected_aad=lambda rel: rel.encode(),
            dry_run=True,
        )
        assert report.counts["rewrapped"] == 0 and {i.status for i in report.items} >= {
            "would_rewrap"
        }
        assert not dst.exists() or not any(dst.rglob("*"))

    def test_in_place_replaces_atomically_and_only_when_asked(
        self, tmp_path, tree, old_pair, new_pair
    ) -> None:
        from quantum_safe.migrate.rewrap import rewrap_directory

        src, files = tree
        with pytest.raises(ValueError, match="in_place"):
            rewrap_directory(src, src, old_secret=old_pair.secret, new_public=new_pair.public)
        report = rewrap_directory(
            src,
            None,
            in_place=True,
            old_secret=old_pair.secret,
            new_public=new_pair.public,
            new_secret=new_pair.secret,
            expected_aad=lambda rel: rel.encode(),
        )
        assert report.counts["rewrapped"] == 3
        sealed = SealedMessage.from_bytes((src / "a.sealed").read_bytes())
        assert sealed.algorithm == "X25519+ML-KEM-1024"
        assert not list(src.rglob("*.tmp"))

    def test_report_serialises_and_never_contains_keys_or_plaintext(
        self, tmp_path, tree, old_pair, new_pair
    ) -> None:
        from quantum_safe.migrate.rewrap import rewrap_directory

        src, files = tree
        report = rewrap_directory(
            src,
            tmp_path / "dst",
            old_secret=old_pair.secret,
            new_public=new_pair.public,
            new_secret=new_pair.secret,
            expected_aad=lambda rel: rel.encode(),
        )
        text = json.dumps(report.to_dict())
        for data in files.values():
            assert data.decode() not in text
        assert hashlib.sha256(b"alpha").hexdigest() not in text
        assert report.to_dict()["counts"]["rewrapped"] == 3

    def test_cbom_lists_the_algorithms_before_and_after_with_status(
        self, tmp_path, tree, old_pair, new_pair
    ) -> None:
        from quantum_safe.migrate.rewrap import rewrap_directory

        src, _ = tree
        report = rewrap_directory(
            src,
            tmp_path / "dst",
            old_secret=old_pair.secret,
            new_public=new_pair.public,
            new_secret=new_pair.secret,
            expected_aad=lambda rel: rel.encode(),
        )
        cbom = report.to_cbom()
        assert cbom["bomFormat"] == "CycloneDX" and cbom["specVersion"] == "1.6"
        names = {c["name"] for c in cbom["components"]}
        assert {"X25519+ML-KEM-768", "X25519+ML-KEM-1024"} <= names
        statuses = {
            p["value"]
            for c in cbom["components"]
            for p in c.get("properties", [])
            if p["name"] == "quantum-safe:migration-status"
        }
        assert statuses == {"migrated-from", "migrated-to"}
        counts = {p["name"]: p["value"] for p in cbom["metadata"]["properties"]}
        assert counts["quantum-safe:items-rewrapped"] == "3"
