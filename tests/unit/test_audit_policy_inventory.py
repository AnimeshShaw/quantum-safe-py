"""
Every AuditPolicy key control has an enforcement path (GitHub issue #8).

The policy used to declare ``min_security_level``, ``hybrid_required``,
``allow_non_nist_standard``, ``require_migration_state`` and
``max_classical_only_keys`` without ever reading them, so a stricter policy gave the
same verdict as a looser one. These tests pin, for each control, one inventory that
passes and one that fails, and that nothing is skipped silently.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from quantum_safe.audit import Auditor, AuditPolicy, InventoryEntry, load_inventory
from quantum_safe.audit.inventory import AlgorithmKind, classify_algorithm
from quantum_safe.migrate.scanner import Finding, Severity
from quantum_safe.types.keys import MigrationState

H = MigrationState.HYBRID_TRANSITION
C = MigrationState.CLASSICAL_ONLY
PP = MigrationState.PQC_PREFERRED
PO = MigrationState.PQC_ONLY

# A policy with only the control under test switched on.
_OFF = {
    "min_security_level": 1,
    "allow_classical_only": True,
    "hybrid_required": False,
    "allow_non_nist_standard": True,
    "require_migration_state": "classical_only",
    "fail_on": ["CRITICAL"],
}


def policy(**overrides) -> AuditPolicy:
    return AuditPolicy(**{**_OFF, **overrides})


def rules(violations) -> list[str]:
    return [v.rule for v in violations]


class TestClassify:
    def test_pqc_kem_and_signature(self) -> None:
        kem = classify_algorithm("ML-KEM-768")
        assert (kem.kind, kem.nist_level, kem.is_nist_standard) == (AlgorithmKind.PQC, 3, True)
        sig = classify_algorithm("ML-DSA-44")
        assert (sig.kind, sig.nist_level) == (AlgorithmKind.PQC, 2)

    def test_classical(self) -> None:
        for name in ("X25519", "Ed25519", "P-256"):
            assert classify_algorithm(name).kind is AlgorithmKind.CLASSICAL

    def test_hybrid_takes_level_of_pqc_half(self) -> None:
        info = classify_algorithm("X25519+ML-KEM-512")
        assert (info.kind, info.nist_level) == (AlgorithmKind.HYBRID, 1)
        assert classify_algorithm("Ed25519+ML-DSA-87").nist_level == 5

    @pytest.mark.parametrize(
        "name",
        ["", "RSA-2048", "ML-KEM-9999", "X25519+ML-DSA-65", "Ed25519+ML-KEM-768", "a+b+c", "+"],
    )
    def test_unknown_names_are_not_guessed(self, name: str) -> None:
        assert classify_algorithm(name).kind is AlgorithmKind.UNKNOWN

    def test_non_nist(self) -> None:
        assert classify_algorithm("BIKE-L1").is_nist_standard is False
        assert classify_algorithm("HQC-128").is_nist_standard is False


class TestMinSecurityLevel:
    def test_level_meets_minimum_passes(self) -> None:
        p = policy(min_security_level=3)
        assert p.evaluate([], [InventoryEntry("k", "ML-KEM-768")]) == []

    def test_level_below_minimum_fails(self) -> None:
        p = policy(min_security_level=3)
        v = p.evaluate([], [InventoryEntry("k", "ML-KEM-512")])
        assert rules(v) == ["min_security_level"]
        assert "key 'k'" in v[0].detail and "level 1" in v[0].detail

    def test_level_one_minimum_accepts_level_one(self) -> None:
        assert policy(min_security_level=1).evaluate([], [InventoryEntry("k", "ML-KEM-512")]) == []

    def test_hybrid_uses_its_pqc_half(self) -> None:
        p = policy(min_security_level=3)
        assert rules(p.evaluate([], [InventoryEntry("k", "X25519+ML-KEM-512")])) == [
            "min_security_level"
        ]
        assert p.evaluate([], [InventoryEntry("k", "X25519+ML-KEM-768")]) == []

    def test_classical_key_has_no_level_to_compare(self) -> None:
        # Classical keys are governed by allow_classical_only / max_classical_only_keys.
        assert policy(min_security_level=5).evaluate([], [InventoryEntry("k", "Ed25519")]) == []


class TestHybridRequired:
    def test_hybrid_passes(self) -> None:
        p = policy(hybrid_required=True)
        assert p.evaluate([], [InventoryEntry("k", "Ed25519+ML-DSA-65")]) == []

    def test_pqc_only_fails(self) -> None:
        p = policy(hybrid_required=True)
        assert rules(p.evaluate([], [InventoryEntry("k", "ML-DSA-65")])) == ["hybrid_required"]

    def test_not_required_accepts_pqc_only(self) -> None:
        assert policy(hybrid_required=False).evaluate([], [InventoryEntry("k", "ML-DSA-65")]) == []


class TestNonNist:
    def test_disallowed_non_nist_fails(self) -> None:
        p = policy(allow_non_nist_standard=False)
        assert rules(p.evaluate([], [InventoryEntry("k", "BIKE-L1")])) == [
            "allow_non_nist_standard"
        ]
        assert rules(p.evaluate([], [InventoryEntry("k", "X25519+ML-KEM-768")])) == []

    def test_allowed_non_nist_passes(self) -> None:
        assert (
            policy(allow_non_nist_standard=True).evaluate([], [InventoryEntry("k", "HQC-128")])
            == []
        )


class TestMigrationState:
    def test_state_at_or_above_minimum_passes(self) -> None:
        p = policy(require_migration_state="hybrid_transition")
        for state in (H, PP, PO):
            assert p.evaluate([], [InventoryEntry("k", "X25519+ML-KEM-768", state)]) == []

    def test_state_below_minimum_fails(self) -> None:
        p = policy(require_migration_state="hybrid_transition")
        v = p.evaluate([], [InventoryEntry("k", "Ed25519", C)])
        assert rules(v) == ["require_migration_state"]

    def test_higher_floor(self) -> None:
        p = policy(require_migration_state="pqc_preferred")
        assert rules(p.evaluate([], [InventoryEntry("k", "X25519+ML-KEM-768", H)])) == [
            "require_migration_state"
        ]
        assert p.evaluate([], [InventoryEntry("k", "X25519+ML-KEM-768", PP)]) == []

    def test_missing_state_fails_when_a_minimum_is_set(self) -> None:
        p = policy(require_migration_state="hybrid_transition")
        v = p.evaluate([], [InventoryEntry("k", "X25519+ML-KEM-768")])
        assert rules(v) == ["require_migration_state"]
        assert "no migration state" in v[0].detail

    def test_missing_state_ok_when_minimum_is_classical_only(self) -> None:
        assert (
            policy(require_migration_state="classical_only").evaluate(
                [], [InventoryEntry("k", "Ed25519")]
            )
            == []
        )

    def test_invalid_minimum_is_rejected_at_construction(self) -> None:
        with pytest.raises(ValueError, match="require_migration_state"):
            AuditPolicy(require_migration_state="hybrid-transition")


class TestMaxClassicalOnly:
    def test_zero_with_no_classical_keys_passes(self) -> None:
        p = policy(max_classical_only_keys=0)
        assert p.evaluate([], [InventoryEntry("k", "X25519+ML-KEM-768")]) == []

    def test_zero_with_one_classical_key_fails(self) -> None:
        p = policy(max_classical_only_keys=0)
        v = p.evaluate([], [InventoryEntry("old", "Ed25519"), InventoryEntry("k", "ML-DSA-65")])
        assert rules(v) == ["max_classical_only_keys"]
        assert "old" in v[0].detail

    def test_at_the_limit_passes_over_it_fails(self) -> None:
        p = policy(max_classical_only_keys=2)
        two = [InventoryEntry("a", "Ed25519"), InventoryEntry("b", "X25519")]
        assert p.evaluate([], two) == []
        assert rules(p.evaluate([], [*two, InventoryEntry("c", "P-256")])) == [
            "max_classical_only_keys"
        ]

    def test_state_classical_only_counts_even_with_a_hybrid_name(self) -> None:
        p = policy(max_classical_only_keys=0)
        v = p.evaluate([], [InventoryEntry("k", "X25519+ML-KEM-768", C)])
        assert rules(v) == ["max_classical_only_keys"]

    def test_allow_classical_only_false_rejects_each_classical_key(self) -> None:
        p = policy(allow_classical_only=False)
        v = p.evaluate([], [InventoryEntry("a", "Ed25519"), InventoryEntry("b", "X25519")])
        assert rules(v) == ["classical_only_key", "classical_only_key"]

    def test_a_limit_governs_instead_of_allow_classical_only(self) -> None:
        p = policy(allow_classical_only=False, max_classical_only_keys=1)
        assert p.evaluate([], [InventoryEntry("a", "Ed25519")]) == []

    @pytest.mark.parametrize("bad", [-1, 1.5, "0", True])
    def test_bad_limit_rejected(self, bad) -> None:
        with pytest.raises(ValueError, match="max_classical_only_keys"):
            AuditPolicy(max_classical_only_keys=bad)


class TestFailClosed:
    def test_unknown_algorithm_is_a_violation(self) -> None:
        v = policy().evaluate([], [InventoryEntry("k", "RSA-2048")])
        assert rules(v) == ["unknown_algorithm"]

    def test_unknown_key_in_a_policy_file_is_rejected(self) -> None:
        with pytest.raises(ValueError, match="min_security_lvl"):
            AuditPolicy.from_dict({"min_security_lvl": 5})

    def test_version_marker_is_accepted(self) -> None:
        assert (
            AuditPolicy.from_dict({"version": 1, "min_security_level": 2}).min_security_level == 2
        )

    @pytest.mark.parametrize(
        "field", ["allow_classical_only", "hybrid_required", "allow_non_nist_standard"]
    )
    def test_string_instead_of_boolean_is_rejected(self, field: str) -> None:
        # "false" is a non-empty string, i.e. truthy.
        with pytest.raises(ValueError, match=field):
            AuditPolicy.from_dict({field: "false"})

    def test_bad_types_for_lists_and_level(self) -> None:
        with pytest.raises(ValueError, match="fail_on"):
            AuditPolicy.from_dict({"fail_on": "HIGH"})
        with pytest.raises(ValueError, match="exempt_paths"):
            AuditPolicy.from_dict({"exempt_paths": "tests/**"})
        with pytest.raises(ValueError, match="min_security_level"):
            AuditPolicy.from_dict({"min_security_level": "3"})
        with pytest.raises(ValueError, match="min_security_level"):
            AuditPolicy.from_dict({"min_security_level": True})

    def test_round_trip_through_dict(self) -> None:
        p = AuditPolicy(max_classical_only_keys=3, require_inventory=True)
        assert AuditPolicy.from_dict(p.to_dict()) == p


class TestCombined:
    def test_all_violations_are_reported_in_input_order(self) -> None:
        p = AuditPolicy(
            min_security_level=3,
            hybrid_required=True,
            allow_non_nist_standard=False,
            require_migration_state="hybrid_transition",
            max_classical_only_keys=0,
            allow_classical_only=True,
            fail_on=["CRITICAL"],
        )
        inv = [
            InventoryEntry("a", "ML-KEM-512"),  # level, hybrid_required, missing state
            InventoryEntry("b", "BIKE-L1", H),  # level, hybrid_required, non-NIST
            InventoryEntry("c", "Ed25519", C),  # state below minimum, plus the count
        ]
        first = rules(p.evaluate([], inv))
        assert first == rules(p.evaluate([], inv))  # deterministic
        assert first == [
            "min_security_level",
            "hybrid_required",
            "require_migration_state",
            "min_security_level",
            "hybrid_required",
            "allow_non_nist_standard",
            "require_migration_state",
            "max_classical_only_keys",
        ]

    def test_exemptions_do_not_exempt_inventory_entries(self) -> None:
        p = policy(max_classical_only_keys=0, exempt_paths=["*"])
        assert rules(p.evaluate([], [InventoryEntry("tests/old", "Ed25519")])) == [
            "max_classical_only_keys"
        ]

    def test_source_findings_and_inventory_are_both_evaluated(self) -> None:
        finding = Finding(
            file="app.py", line=3, col=1, severity=Severity.CRITICAL, rule_id="QS001", message="x"
        )
        p = policy(max_classical_only_keys=0)
        v = p.evaluate([finding], [InventoryEntry("old", "Ed25519")])
        assert rules(v) == ["critical_vulnerability", "max_classical_only_keys"]

    def test_empty_inventory_means_no_keys_and_passes_key_controls(self) -> None:
        assert AuditPolicy.strict().evaluate([], []) == []


class TestNothingIsSkippedSilently:
    def test_active_controls_are_listed_when_no_inventory(self) -> None:
        assert AuditPolicy().unevaluated_controls(None) == [
            "min_security_level",
            "hybrid_required",
            "allow_non_nist_standard",
            "require_migration_state",
        ]
        assert "max_classical_only_keys" in policy(max_classical_only_keys=0).unevaluated_controls(
            None
        )

    def test_permissive_has_nothing_to_evaluate(self) -> None:
        assert AuditPolicy.permissive().unevaluated_controls(None) == []

    def test_nothing_is_unevaluated_with_an_inventory(self) -> None:
        assert AuditPolicy.strict().unevaluated_controls([]) == []

    def test_require_inventory_turns_it_into_a_violation(self) -> None:
        p = AuditPolicy(require_inventory=True)
        v = p.evaluate([])
        assert rules(v) == ["inventory_required"]
        assert "min_security_level" in v[0].detail
        assert p.evaluate([], []) == []

    def test_require_inventory_with_no_active_controls_is_satisfied(self) -> None:
        assert AuditPolicy(**{**_OFF, "require_inventory": True}).evaluate([]) == []

    def test_report_without_inventory_names_the_controls(self) -> None:
        report = Auditor.audit_source("x = 1\n", policy=AuditPolicy.strict())
        assert report.passed
        assert "min_security_level" in report.unevaluated_controls
        assert report.to_dict()["unevaluated_controls"] == report.unevaluated_controls
        assert "controls not evaluated" in report.summary_line()
        assert "Not evaluated" in report.to_github_summary()

    def test_report_with_inventory_evaluates_and_fails(self) -> None:
        report = Auditor.audit_source(
            "x = 1\n",
            policy=AuditPolicy.strict(),
            inventory=[InventoryEntry("k", "ML-KEM-512", H)],
        )
        assert not report.passed
        assert report.unevaluated_controls == []
        assert "min_security_level" in rules(report.policy_violations)
        assert report.to_dict()["inventory_keys"] == 1

    def test_audit_directory_and_ci_gate_accept_an_inventory(self, tmp_path: Path) -> None:
        (tmp_path / "ok.py").write_text("x = 1\n")
        bad = [InventoryEntry("old", "Ed25519", C)]
        good = [InventoryEntry("new", "X25519+ML-KEM-768", H)]
        p = AuditPolicy.strict()
        assert not Auditor.audit(tmp_path, policy=p, inventory=bad).passed
        assert Auditor.audit(tmp_path, policy=p, inventory=good).passed
        assert Auditor.ci_gate(tmp_path, policy=p, inventory=bad) == 1
        assert Auditor.ci_gate(tmp_path, policy=p, inventory=good) == 0


class TestPresets:
    def test_transition_tolerates_classical_keys(self) -> None:
        inv = [InventoryEntry("old", "Ed25519", C), InventoryEntry("new", "X25519+ML-KEM-768", H)]
        assert AuditPolicy.transition().evaluate([], inv) == []
        assert AuditPolicy.permissive().evaluate([], inv) == []

    def test_strict_rejects_classical_and_weak(self) -> None:
        inv = [InventoryEntry("old", "Ed25519", C), InventoryEntry("weak", "X25519+ML-KEM-512", H)]
        assert {"classical_only_key", "min_security_level"} <= set(
            rules(AuditPolicy.strict().evaluate([], inv))
        )


class TestInventoryFile:
    def test_load_list_and_wrapped(self, tmp_path: Path) -> None:
        entries = [
            {"key_id": "a", "algorithm": "Ed25519", "migration_state": "classical_only"},
            {"key_id": "b", "algorithm": "X25519+ML-KEM-768"},
        ]
        for name, payload in (("l.json", entries), ("w.json", {"keys": entries})):
            f = tmp_path / name
            f.write_text(json.dumps(payload))
            inv = load_inventory(f)
            assert [e.key_id for e in inv] == ["a", "b"]
            assert inv[0].migration_state is C and inv[1].migration_state is None

    @pytest.mark.parametrize(
        "payload",
        [
            "not json",
            "{}",
            '{"keys": [], "extra": 1}',
            '"x"',
            '[{"algorithm": "Ed25519"}]',
            '[{"key_id": "a"}]',
            '[{"key_id": "a", "algorithm": "Ed25519", "migration_state": "done"}]',
            '[{"key_id": "a", "algorithm": "Ed25519", "colour": "red"}]',
            "[1]",
        ],
    )
    def test_malformed_inventory_is_rejected(self, tmp_path: Path, payload: str) -> None:
        f = tmp_path / "inv.json"
        f.write_text(payload)
        with pytest.raises(ValueError):
            load_inventory(f)


click = pytest.importorskip("click")
from click.testing import CliRunner  # noqa: E402

from quantum_safe.audit.cli import _cli as audit_cli  # type: ignore[attr-defined]  # noqa: E402


class TestCli:
    @pytest.fixture
    def src(self, tmp_path: Path) -> Path:
        d = tmp_path / "src"
        d.mkdir()
        (d / "ok.py").write_text("x = 1\n")
        return d

    def _run(self, *args: str):
        return CliRunner().invoke(audit_cli, ["scan", *args])

    def test_inventory_violation_fails_the_gate(self, src: Path, tmp_path: Path) -> None:
        inv = tmp_path / "inv.json"
        inv.write_text(json.dumps([{"key_id": "old", "algorithm": "Ed25519"}]))
        result = self._run(str(src), "--preset-policy", "strict", "--inventory", str(inv))
        assert result.exit_code == 1
        assert "classical_only_key" in result.output

    def test_good_inventory_passes(self, src: Path, tmp_path: Path) -> None:
        inv = tmp_path / "inv.json"
        inv.write_text(
            json.dumps(
                [
                    {
                        "key_id": "k",
                        "algorithm": "X25519+ML-KEM-768",
                        "migration_state": "pqc_preferred",
                    }
                ]
            )
        )
        result = self._run(str(src), "--preset-policy", "strict", "--inventory", str(inv))
        assert result.exit_code == 0, result.output
        assert "Not evaluated" not in result.output

    def test_without_inventory_the_output_says_what_was_not_checked(self, src: Path) -> None:
        result = self._run(str(src), "--preset-policy", "strict")
        assert result.exit_code == 0
        assert "Not evaluated" in result.output and "min_security_level" in result.output

    def test_unreadable_inventory_is_an_error_not_a_pass(self, src: Path, tmp_path: Path) -> None:
        inv = tmp_path / "inv.json"
        inv.write_text("[{")
        result = self._run(str(src), "--inventory", str(inv))
        assert result.exit_code != 0
        assert "invalid inventory" in result.output

    def test_malformed_policy_file_is_an_error(self, src: Path, tmp_path: Path) -> None:
        pol = tmp_path / "policy.json"
        pol.write_text(json.dumps({"min_security_lvl": 5}))
        result = self._run(str(src), "--policy", str(pol))
        assert result.exit_code != 0
        assert "invalid policy file" in result.output
