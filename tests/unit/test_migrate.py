"""
Unit tests for quantum_safe.migrate

The scanner tests operate on in-memory source strings — no disk I/O.
The state machine tests use a plain dict as the backing store.
The upgrader tests use a mock PQC backend.
Shim tests check warning/logging behavior and call counting.
"""

from __future__ import annotations

import warnings

import pytest

from quantum_safe.exceptions import UnsupportedAlgorithm
from quantum_safe.migrate.scanner import (
    Finding,
    ScanReport,
    Scanner,
    Severity,
)
from quantum_safe.migrate.state import (
    MigrationRecord,
    MigrationStateManager,
)
from quantum_safe.migrate.upgrader import UpgradeResult, Upgrader
from quantum_safe.types import KeyPair, MigrationState, PublicKey, SecretKey


# ---------------------------------------------------------------------------
# Scanner: rule matching against source strings
# ---------------------------------------------------------------------------


class TestScannerRSA:
    def test_rsa_generate_detected(self):
        src = """
from cryptography.hazmat.primitives.asymmetric import rsa
key = rsa.generate_private_key(65537, 2048)
"""
        report = Scanner.scan_source(src, filename="test.py")
        assert any(f.rule_id == "QS001" for f in report.findings)

    def test_rsa_oaep_detected(self):
        src = """
from cryptography.hazmat.primitives.asymmetric import padding
enc = padding.OAEP(mgf=padding.MGF1(), algorithm=hashes.SHA256(), label=None)
"""
        report = Scanner.scan_source(src)
        assert any(f.rule_id == "QS003" for f in report.findings)

    def test_rsa_pkcs1v15_detected(self):
        src = """
from cryptography.hazmat.primitives.asymmetric import padding
p = padding.PKCS1v15()
"""
        report = Scanner.scan_source(src)
        assert any(f.rule_id == "QS002" for f in report.findings)


class TestScannerECDSA:
    def test_ecdsa_keygen_detected(self):
        src = """
from cryptography.hazmat.primitives.asymmetric import ec
key = ec.generate_private_key(ec.SECP256R1())
"""
        report = Scanner.scan_source(src)
        assert any(f.rule_id == "QS010" for f in report.findings)

    def test_ecdh_detected(self):
        src = """
from cryptography.hazmat.primitives.asymmetric.ec import ECDH
shared = priv.exchange(ECDH(), peer_pub)
"""
        report = Scanner.scan_source(src)
        # ECDH import should trigger QS011
        assert any(f.rule_id in ("QS010", "QS011") for f in report.findings)


class TestScannerWeakAlgos:
    def test_md5_string_detected(self):
        src = 'algo = "MD5"'
        report = Scanner.scan_source(src)
        assert any(f.rule_id == "QS031" for f in report.findings)

    def test_sha1_string_detected(self):
        src = 'digest = hashlib.new("SHA-1")'
        report = Scanner.scan_source(src)
        assert any(f.rule_id == "QS030" for f in report.findings)

    def test_aes128_string_detected(self):
        src = 'cipher = "AES-128-CBC"'
        report = Scanner.scan_source(src)
        assert any(f.rule_id == "QS020" for f in report.findings)

    def test_3des_string_detected(self):
        src = 'algo = "3DES"'
        report = Scanner.scan_source(src)
        assert any(f.rule_id == "QS021" for f in report.findings)


class TestScannerJWT:
    def test_rs256_jwt_algo_detected(self):
        src = 'token = jwt.encode(payload, key, algorithm="RS256")'
        report = Scanner.scan_source(src)
        assert any(f.rule_id == "QS040" for f in report.findings)

    def test_es256_detected(self):
        src = 'algorithms = ["ES256", "ES384"]'
        report = Scanner.scan_source(src)
        assert any(f.rule_id == "QS040" for f in report.findings)


class TestScannerDSA:
    def test_dsa_is_critical(self):
        src = """
from cryptography.hazmat.primitives.asymmetric import dsa
key = dsa.generate_private_key(key_size=2048)
"""
        report = Scanner.scan_source(src)
        dsa_findings = [f for f in report.findings if f.rule_id == "QS015"]
        assert dsa_findings
        assert dsa_findings[0].severity == Severity.CRITICAL


class TestScannerCleanCode:
    def test_quantum_safe_code_has_no_findings(self):
        src = """
from quantum_safe import HybridKEM, HybridSign
kem = HybridKEM()
kp  = kem.generate_keypair()
ct, ss = kem.encapsulate(kp.public)
ss2    = kem.decapsulate(kp.secret, ct)
"""
        report = Scanner.scan_source(src)
        # Should have no classical crypto findings
        classical = [f for f in report.findings if f.severity >= Severity.HIGH]
        assert not classical

    def test_comment_mentioning_rsa_not_flagged(self):
        # An RSA mention in a string that's not an algorithm parameter
        # won't be flagged by call-matching (only string patterns catch it)
        src = """
# This module replaces RSA with quantum-safe alternatives
description = "Replaces old RSA based authentication"
"""
        report = Scanner.scan_source(src)
        # No critical/high — RSA is a comment/description, not a call
        high_plus = [f for f in report.findings if f.severity >= Severity.HIGH]
        assert not high_plus


class TestScanReport:
    def test_has_blocking_findings_true(self):
        report = ScanReport(root="test")
        report.findings.append(Finding(
            file="a.py", line=1, col=1,
            severity=Severity.HIGH,
            rule_id="QS001",
            message="RSA detected",
        ))
        assert report.has_blocking_findings

    def test_has_blocking_findings_false_on_medium(self):
        report = ScanReport(root="test")
        report.findings.append(Finding(
            file="a.py", line=1, col=1,
            severity=Severity.MEDIUM,
            rule_id="QS020",
            message="AES-128",
        ))
        assert not report.has_blocking_findings

    def test_summary_format(self):
        report = ScanReport(root="./src", files_scanned=42)
        report.findings.append(Finding(
            file="a.py", line=1, col=1,
            severity=Severity.CRITICAL,
            rule_id="QS031",
            message="MD5",
        ))
        s = report.summary()
        assert "42" in s
        assert "CRITICAL" in s

    def test_to_json_is_valid(self):
        import json
        report = Scanner.scan_source(
            'from cryptography.hazmat.primitives.asymmetric import rsa'
        )
        data = json.loads(report.to_json())
        assert "findings" in data
        assert isinstance(data["findings"], list)

    def test_to_sarif_structure(self):
        report = Scanner.scan_source(
            'from cryptography.hazmat.primitives.asymmetric import rsa\n'
            'key = rsa.generate_private_key(65537, 2048)'
        )
        sarif = report.to_sarif()
        assert sarif["version"] == "2.1.0"
        assert "runs" in sarif
        assert len(sarif["runs"]) == 1
        run = sarif["runs"][0]
        assert "tool" in run
        assert "results" in run
        # Each finding should have a location
        for result in run["results"]:
            assert result["locations"][0]["physicalLocation"]["region"]["startLine"] > 0

    def test_finding_str_format(self):
        f = Finding(
            file="src/auth.py", line=42, col=5,
            severity=Severity.HIGH,
            rule_id="QS001",
            message="RSA detected",
        )
        s = str(f)
        assert "QS001" in s
        assert "42" in s
        assert "HIGH" in s


class TestScannerSyntaxError:
    def test_syntax_error_file_reported_not_crashed(self):
        src = "def broken(: this is not valid python"
        report = Scanner.scan_source(src, filename="broken.py")
        assert len(report.errors) == 1
        assert "broken.py" in report.errors[0]["file"]

    def test_files_scanned_not_incremented_on_error(self):
        src = "def broken(: invalid"
        report = Scanner.scan_source(src)
        assert report.files_scanned == 0


class TestScannerDirectory:
    def test_scan_directory_returns_report(self, tmp_path):
        # Write some Python files to a temp dir
        (tmp_path / "clean.py").write_text("x = 1 + 1\n")
        (tmp_path / "classical.py").write_text(
            'from cryptography.hazmat.primitives.asymmetric import rsa\n'
        )
        subdir = tmp_path / "subpkg"
        subdir.mkdir()
        (subdir / "__init__.py").write_text("")

        report = Scanner.scan_directory(tmp_path)
        assert report.files_scanned >= 2
        assert report.root == str(tmp_path)

    def test_scan_directory_excludes_pycache(self, tmp_path):
        pycache = tmp_path / "__pycache__"
        pycache.mkdir()
        (pycache / "hidden.py").write_text('import rsa\n')
        (tmp_path / "normal.py").write_text("x = 1\n")

        report = Scanner.scan_directory(tmp_path)
        # __pycache__ files should be excluded
        for f in report.findings:
            assert "__pycache__" not in f.file


# ---------------------------------------------------------------------------
# Migration state machine
# ---------------------------------------------------------------------------


class TestMigrationRecord:
    def _make_record(self, from_s, to_s) -> MigrationRecord:
        return MigrationRecord(
            record_id="test-id",
            key_id="key-abc",
            from_state=from_s,
            to_state=to_s,
            algorithm="X25519+ML-KEM-768",
            timestamp=1700000000.0,
            actor="test-suite",
            reason="",
        )

    def test_is_forward_classical_to_hybrid(self):
        rec = self._make_record(
            MigrationState.CLASSICAL_ONLY,
            MigrationState.HYBRID_TRANSITION,
        )
        assert rec.is_forward
        assert not rec.is_backward

    def test_is_backward_hybrid_to_classical(self):
        rec = self._make_record(
            MigrationState.HYBRID_TRANSITION,
            MigrationState.CLASSICAL_ONLY,
        )
        assert rec.is_backward
        assert not rec.is_forward

    def test_serialization_round_trip(self):
        rec = self._make_record(
            MigrationState.CLASSICAL_ONLY,
            MigrationState.HYBRID_TRANSITION,
        )
        data = rec.to_bytes()
        rec2 = MigrationRecord.from_bytes(data)
        assert rec2.record_id == rec.record_id
        assert rec2.from_state == rec.from_state
        assert rec2.to_state == rec.to_state
        assert rec2.algorithm == rec.algorithm

    def test_to_dict_has_expected_keys(self):
        rec = self._make_record(
            MigrationState.CLASSICAL_ONLY,
            MigrationState.HYBRID_TRANSITION,
        )
        d = rec.to_dict()
        for key in ("record_id", "key_id", "from_state", "to_state", "algorithm", "timestamp"):
            assert key in d


class TestMigrationStateManager:
    def _make_mgr(self) -> MigrationStateManager:
        return MigrationStateManager(store={})

    def test_initial_state_is_none(self):
        mgr = self._make_mgr()
        assert mgr.get_current_state("nonexistent-key") is None

    def test_transition_stores_state(self):
        mgr = self._make_mgr()
        rec = mgr.transition(
            key_id="key1",
            from_state=MigrationState.CLASSICAL_ONLY,
            to_state=MigrationState.HYBRID_TRANSITION,
            algorithm="X25519+ML-KEM-768",
            actor="test",
        )
        assert mgr.get_current_state("key1") == MigrationState.HYBRID_TRANSITION
        assert rec.to_state == MigrationState.HYBRID_TRANSITION

    def test_transition_sequence(self):
        mgr = self._make_mgr()
        mgr.transition("k","key1", MigrationState.CLASSICAL_ONLY, MigrationState.HYBRID_TRANSITION, "X25519+ML-KEM-768") if False else None
        # Full sequence
        mgr.transition("key1", MigrationState.CLASSICAL_ONLY, MigrationState.HYBRID_TRANSITION, "X25519+ML-KEM-768")
        mgr.transition("key1", MigrationState.HYBRID_TRANSITION, MigrationState.PQC_PREFERRED, "X25519+ML-KEM-768")
        mgr.transition("key1", MigrationState.PQC_PREFERRED, MigrationState.PQC_ONLY, "ML-KEM-768")
        assert mgr.get_current_state("key1") == MigrationState.PQC_ONLY

    def test_invalid_transition_raises(self):
        mgr = self._make_mgr()
        with pytest.raises(ValueError, match="Invalid transition"):
            mgr.transition(
                "key1",
                MigrationState.CLASSICAL_ONLY,
                MigrationState.PQC_ONLY,  # skip states
                "ML-KEM-768",
            )

    def test_backward_without_allow_raises(self):
        mgr = self._make_mgr()
        mgr.transition("key1", MigrationState.CLASSICAL_ONLY, MigrationState.HYBRID_TRANSITION, "X25519+ML-KEM-768")
        with pytest.raises(ValueError, match="allow_backward"):
            mgr.transition(
                "key1",
                MigrationState.HYBRID_TRANSITION,
                MigrationState.CLASSICAL_ONLY,
                "X25519",
            )

    def test_backward_without_reason_raises(self):
        mgr = self._make_mgr()
        mgr.transition("key1", MigrationState.CLASSICAL_ONLY, MigrationState.HYBRID_TRANSITION, "X25519+ML-KEM-768")
        with pytest.raises(ValueError, match="reason"):
            mgr.transition(
                "key1",
                MigrationState.HYBRID_TRANSITION,
                MigrationState.CLASSICAL_ONLY,
                "X25519",
                allow_backward=True,
                reason="",  # empty
            )

    def test_backward_with_reason_succeeds(self):
        mgr = self._make_mgr()
        mgr.transition("key1", MigrationState.CLASSICAL_ONLY, MigrationState.HYBRID_TRANSITION, "X25519+ML-KEM-768")
        rec = mgr.transition(
            "key1",
            MigrationState.HYBRID_TRANSITION,
            MigrationState.CLASSICAL_ONLY,
            "X25519",
            allow_backward=True,
            reason="Emergency rollback — ML-KEM security concern",
        )
        assert rec.is_backward
        assert mgr.get_current_state("key1") == MigrationState.CLASSICAL_ONLY

    def test_history_grows(self):
        mgr = self._make_mgr()
        mgr.transition("key1", MigrationState.CLASSICAL_ONLY, MigrationState.HYBRID_TRANSITION, "X25519+ML-KEM-768")
        mgr.transition("key1", MigrationState.HYBRID_TRANSITION, MigrationState.PQC_PREFERRED, "X25519+ML-KEM-768")
        history = mgr.get_history("key1")
        assert len(history) == 2
        assert history[0].from_state == MigrationState.CLASSICAL_ONLY
        assert history[1].from_state == MigrationState.HYBRID_TRANSITION

    def test_stale_state_raises(self):
        mgr = self._make_mgr()
        mgr.transition("key1", MigrationState.CLASSICAL_ONLY, MigrationState.HYBRID_TRANSITION, "X25519+ML-KEM-768")
        # Now try to transition from CLASSICAL_ONLY again (stale)
        with pytest.raises(ValueError, match="Concurrent modification"):
            mgr.transition("key1", MigrationState.CLASSICAL_ONLY, MigrationState.HYBRID_TRANSITION, "X25519+ML-KEM-768")

    def test_needs_migration_list(self):
        mgr = self._make_mgr()
        mgr.transition("key-a", MigrationState.CLASSICAL_ONLY, MigrationState.HYBRID_TRANSITION, "algo")
        mgr.transition("key-b", MigrationState.CLASSICAL_ONLY, MigrationState.HYBRID_TRANSITION, "algo")
        mgr.transition("key-b", MigrationState.HYBRID_TRANSITION, MigrationState.PQC_PREFERRED, "algo")
        # key-a is HYBRID (migrated enough), key-b is PQC_PREFERRED
        # Neither is CLASSICAL_ONLY now, so needs_migration should be empty
        assert mgr.needs_migration() == []

    def test_migration_progress_counts(self):
        mgr = self._make_mgr()
        mgr.transition("k1", MigrationState.CLASSICAL_ONLY, MigrationState.HYBRID_TRANSITION, "a")
        mgr.transition("k2", MigrationState.CLASSICAL_ONLY, MigrationState.HYBRID_TRANSITION, "a")
        mgr.transition("k2", MigrationState.HYBRID_TRANSITION, MigrationState.PQC_PREFERRED, "a")
        progress = mgr.migration_progress()
        assert progress[MigrationState.HYBRID_TRANSITION.value] == 1
        assert progress[MigrationState.PQC_PREFERRED.value] == 1


# ---------------------------------------------------------------------------
# Upgrader
# ---------------------------------------------------------------------------


class MockKEMBackend:
    name = "mock"
    def keygen(self, a): return b"\xAA" * 1184, b"\xBB" * 2400
    def encapsulate(self, a, p): return b"\xCC" * 1088, b"\xDD" * 32
    def decapsulate(self, a, s, c): return b"\xDD" * 32
    def is_available(self): return True
    def supported_algorithms(self):
        from quantum_safe.backends.base import AlgorithmInfo
        return [AlgorithmInfo("ML-KEM-768", 3, 1184, 2400, 1088, True, False, True)]


class MockSigBackend:
    name = "mock"
    def keygen(self, a): return b"\xAA" * 1952, b"\xBB" * 4000
    def sign(self, a, sk, msg, ctx=b""): return b"\xCC" * 3293
    def verify(self, a, pk, msg, sig, ctx=b""): return True
    def is_available(self): return True
    def supported_algorithms(self): return []


class TestUpgrader:
    def test_upgrade_kem_key(self, monkeypatch):
        from quantum_safe.backends import _load_liboqs_kem
        monkeypatch.setattr(
            "quantum_safe.backends._load_liboqs_kem",
            lambda: MockKEMBackend()
        )
        monkeypatch.setattr(
            "quantum_safe.backends._load_rustcrypto_kem",
            lambda: MockKEMBackend()
        )

        result = Upgrader.upgrade_kem_key(
            classical_secret_bytes=b"\x01" * 32,
            classical_public_bytes=b"\x02" * 32,
            classical_algorithm="X25519",
            target_pqc="ML-KEM-768",
        )
        assert isinstance(result, UpgradeResult)
        assert result.old_algorithm == "X25519"
        assert result.new_algorithm == "X25519+ML-KEM-768"
        assert result.backward_compat
        assert result.migration_state == MigrationState.HYBRID_TRANSITION
        assert result.new_keypair.algorithm == "X25519+ML-KEM-768"

    def test_upgrade_preserves_classical_pub(self, monkeypatch):
        from quantum_safe.kem.hybrid import _unpack_components
        monkeypatch.setattr(
            "quantum_safe.backends._load_liboqs_kem", lambda: MockKEMBackend()
        )
        monkeypatch.setattr(
            "quantum_safe.backends._load_rustcrypto_kem", lambda: MockKEMBackend()
        )

        classical_pub = b"\xDE" * 32
        result = Upgrader.upgrade_kem_key(
            classical_secret_bytes=b"\x01" * 32,
            classical_public_bytes=classical_pub,
            classical_algorithm="X25519",
            target_pqc="ML-KEM-768",
        )
        # Unpack and verify classical component is preserved
        unpacked_pub, _ = _unpack_components(result.new_keypair.public.raw_bytes)
        assert unpacked_pub == classical_pub

    def test_check_needs_upgrade(self):
        classical_pk = PublicKey(
            raw=b"\x01" * 32,
            algorithm="X25519",
            migration_state=MigrationState.CLASSICAL_ONLY,
        )
        classical_sk = SecretKey(
            raw=b"\x02" * 32,
            algorithm="X25519",
            migration_state=MigrationState.CLASSICAL_ONLY,
        )
        kp = KeyPair(public=classical_pk, secret=classical_sk)
        assert Upgrader.check_needs_upgrade(kp)

    def test_check_does_not_need_upgrade_when_hybrid(self):
        hybrid_pk = PublicKey(
            raw=b"\x01" * 50,
            algorithm="X25519+ML-KEM-768",
            migration_state=MigrationState.HYBRID_TRANSITION,
        )
        hybrid_sk = SecretKey(
            raw=b"\x02" * 50,
            algorithm="X25519+ML-KEM-768",
            migration_state=MigrationState.HYBRID_TRANSITION,
        )
        kp = KeyPair(public=hybrid_pk, secret=hybrid_sk)
        assert not Upgrader.check_needs_upgrade(kp)

    def test_describe_key_classical_only(self):
        pk = PublicKey(
            raw=b"\x01" * 32,
            algorithm="X25519",
            migration_state=MigrationState.CLASSICAL_ONLY,
        )
        sk = SecretKey(
            raw=b"\x02" * 32,
            algorithm="X25519",
            migration_state=MigrationState.CLASSICAL_ONLY,
        )
        kp = KeyPair(public=pk, secret=sk)
        desc = Upgrader.describe_key(kp)
        assert desc["needs_upgrade"] is True
        assert "upgrade" in desc["recommendation"].lower()
        assert desc["is_hybrid"] is False


# ---------------------------------------------------------------------------
# Shims — warning behavior and call counting
# ---------------------------------------------------------------------------


class TestFernetShim:
    def test_warns_on_creation(self):
        from quantum_safe.migrate.shims import FernetShim
        from quantum_safe.kem.hybrid import HybridKEM

        class MockPQCBackend:
            name = "mock"
            def keygen(self, a): return b"\xAA" * 1184, b"\xBB" * 2400
            def encapsulate(self, a, p): return b"\xCC" * 1088, b"\xDD" * 32
            def decapsulate(self, a, s, c): return b"\xDD" * 32
            def is_available(self): return True
            def supported_algorithms(self): 
                class DummyAlgo: name = "ML-KEM-768"
                return [DummyAlgo()]

        # Patch the backend resolution so FernetShim doesn't need liboqs
        import quantum_safe.kem.hybrid as _hybrid
        original_get = _hybrid.get_kem_backend

        def mock_get(name="auto"):
            return MockPQCBackend()

        _hybrid.get_kem_backend = mock_get
        try:
            with pytest.warns(DeprecationWarning, match="FernetShim"):
                shim = FernetShim()
            assert shim is not None
        finally:
            _hybrid.get_kem_backend = original_get

    def test_shim_stats_counts(self):
        from quantum_safe.migrate.shims import FernetShim
        # Reset counter
        FernetShim._call_count = 0
        import quantum_safe.kem.hybrid as _hybrid
        original = _hybrid.get_kem_backend

        class FakeBackend:
            name = "mock"
            def keygen(self, a): return b"\xAA" * 1184, b"\xBB" * 2400
            def encapsulate(self, a, p): return b"\xCC" * 1088, b"\xDD" * 32
            def decapsulate(self, a, s, c): return b"\xDD" * 32
            def is_available(self): return True
            def supported_algorithms(self): 
                class DummyAlgo: name = "ML-KEM-768"
                return [DummyAlgo()]

        _hybrid.get_kem_backend = lambda name="auto": FakeBackend()
        try:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                shim = FernetShim()
            stats = FernetShim.shim_stats()
            assert stats["call_count"] >= 1
            assert stats["shim"] == "FernetShim"
        finally:
            _hybrid.get_kem_backend = original
