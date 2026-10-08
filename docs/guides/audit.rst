Audit and compliance
====================

CI audit gate
-------------

:meth:`~quantum_safe.audit.auditor.Auditor.ci_gate` is the recommended
entry point for CI pipelines.  It scans a directory, evaluates a policy,
optionally writes SARIF/JSON output, and returns an exit code:

.. code-block:: python

   import sys
   from quantum_safe.audit import Auditor, AuditPolicy

   exit_code = Auditor.ci_gate(
       "./src",
       policy=AuditPolicy(allow_classical_only=False, hybrid_required=True),
       output_sarif="audit.sarif",    # GitHub Code Scanning
       output_json="audit.json",
   )
   sys.exit(exit_code)

Audit policies
--------------

:class:`~quantum_safe.audit.policy.AuditPolicy` decides what blocks the gate.
Three presets exist as class methods, and ``AuditPolicy()`` is the default:

.. list-table::
   :widths: 20 80
   :header-rows: 1

   * - Policy
     - Behaviour
   * - ``AuditPolicy.permissive()``
     - Fails on CRITICAL findings only. Classical-only and non-NIST keys are tolerated.
   * - ``AuditPolicy.transition()``
     - Fails on CRITICAL findings only. Hybrid is required for post-quantum keys; classical-only keys are tolerated.
   * - ``AuditPolicy()``
     - Fails on HIGH and CRITICAL findings. **Default.**
   * - ``AuditPolicy.strict()``
     - Fails on MEDIUM and above. No classical-only keys, hybrid required.

.. code-block:: python

   from quantum_safe.audit import AuditPolicy

   policy = AuditPolicy.strict()

   # Or configure it. A wrong type or an unknown field raises ValueError,
   # so a typo cannot silently weaken a policy.
   policy = AuditPolicy(
       min_security_level=3,
       hybrid_required=True,
       max_classical_only_keys=0,
       fail_on=["CRITICAL", "HIGH"],
   )

What each field enforces
~~~~~~~~~~~~~~~~~~~~~~~~

The scanner reads **source code**. Some controls are about **keys**, which the
scanner cannot see, so they are checked against a *key inventory* that you pass in.

.. list-table::
   :widths: 28 72
   :header-rows: 1

   * - Field
     - Enforcement
   * - ``fail_on``, ``exempt_paths``, ``allow_classical_only``
     - Source findings at a ``fail_on`` severity are violations unless the file matches
       ``exempt_paths``. With ``allow_classical_only=True`` only CRITICAL findings count.
       Exemptions apply to source findings only, never to inventory entries.
   * - ``min_security_level``
     - Inventory: a key whose post-quantum part has a lower NIST level is a violation.
       Classical keys have no level and are governed by the two fields below.
   * - ``hybrid_required``
     - Inventory: a post-quantum-only key is a violation.
   * - ``allow_non_nist_standard``
     - Inventory: with ``False``, a key whose post-quantum algorithm is not a NIST
       standard (BIKE, HQC) is a violation.
   * - ``require_migration_state``
     - Inventory: the lowest acceptable ``MigrationState``
       (``classical_only`` < ``hybrid_transition`` < ``pqc_preferred`` < ``pqc_only``).
       A lower state is a violation, and so is a missing state unless the minimum is
       ``classical_only``.
   * - ``max_classical_only_keys``
     - Inventory: more classical-only keys than this is one violation. When set, it
       replaces the per-key check that ``allow_classical_only=False`` would apply.
   * - ``require_inventory``
     - If ``True``, auditing without an inventory is itself a violation whenever one of
       the controls above is active.

An algorithm name that is not in the library's registries is reported as a violation
(``unknown_algorithm``), not skipped. A policy file or inventory that cannot be read
stops ``qs-audit scan`` with a non-zero exit.

**Without an inventory** the key controls cannot be evaluated. The audit still runs
and the source-code controls still apply, but the report lists the controls that were
not checked (``report.unevaluated_controls``, the ``unevaluated_controls`` JSON field,
the CLI text output and the GitHub summary) so a pass is never mistaken for a pass on
those controls. Set ``require_inventory=True`` to make that a failure.

.. code-block:: python

   from quantum_safe.audit import Auditor, AuditPolicy, InventoryEntry
   from quantum_safe.types.keys import MigrationState

   inventory = [
       InventoryEntry("signing-2026", "Ed25519+ML-DSA-65", MigrationState.HYBRID_TRANSITION),
       InventoryEntry("legacy-tls", "P-256", MigrationState.CLASSICAL_ONLY),
   ]
   report = Auditor.audit("./src", policy=AuditPolicy.strict(), inventory=inventory)
   for v in report.policy_violations:
       print(v)          # [HIGH] classical_only_key: key 'legacy-tls' (P-256) has no ...

On the command line the inventory is a JSON file, either a list or ``{"keys": [...]}``,
with ``key_id``, ``algorithm`` and optionally ``migration_state`` per entry:

.. code-block:: console

   $ qs-audit scan ./src --preset-policy strict --inventory keys.json

Auditor
-------

:class:`~quantum_safe.audit.auditor.Auditor` exposes the full audit
pipeline for programmatic use:

.. code-block:: python

   from quantum_safe.audit import Auditor, AuditPolicy

   report = Auditor.audit("./src", policy=AuditPolicy())     # a directory or a file
   print(report.summary_line())

   # Or a string of source code
   report = Auditor.audit_source("import rsa\n", policy=AuditPolicy())

   for f in report.scan_report.findings:
       print(f.file, f.line, f.rule_id, f.message, f.fix_hint)

NIST compliance report
----------------------

:class:`~quantum_safe.audit.compliance.NISTComplianceChecker` maps scanner
findings to specific NIST/CISA controls:

.. code-block:: python

   from quantum_safe.audit import NISTComplianceChecker
   from quantum_safe.migrate import Scanner

   scan   = Scanner.scan_directory("./src")
   report = NISTComplianceChecker.check(scan, target="./src")
   print(report.to_json())

Each finding is annotated with the relevant standards:

- FIPS 203 (ML-KEM)
- FIPS 204 (ML-DSA)
- FIPS 205 (SLH-DSA)
- NIST SP 800-208
- CISA Post-Quantum Cryptography Checklist

CycloneDX SBOM enrichment
--------------------------

:class:`~quantum_safe.audit.sbom.SBOMEnricher` annotates a CycloneDX SBOM
with PQC-readiness assessments for each component:

.. code-block:: python

   import json
   from quantum_safe.audit import SBOMEnricher

   with open("sbom.json") as f:
       sbom = json.load(f)

   enriched, assessments = SBOMEnricher.enrich(sbom)

   not_ready = [a for a in assessments if a.readiness.value == "NOT_READY"]
   for a in not_ready:
       print(f"NOT READY: {a.name} {a.version}")
       print(f"  Action: {a.action}")

   with open("sbom-pqc.json", "w") as f:
       json.dump(enriched, f, indent=2)

Readiness values:

- ``READY`` — uses hybrid or pure PQC algorithms
- ``PARTIAL`` — partially migrated
- ``NOT_READY`` — classical-only
- ``UNKNOWN`` — insufficient information

From a ``requirements.txt``:

.. code-block:: python

   enriched, assessments = SBOMEnricher.from_requirements("requirements.txt")

CLI
---

.. code-block:: bash

   # Scan with text output (default)
   qs-audit scan ./src

   # SARIF for GitHub Code Scanning
   qs-audit scan ./src --format sarif --output audit.sarif

   # JSON report
   qs-audit scan ./src --format json --output audit.json

   # Use a policy preset
   qs-audit scan ./src --preset-policy strict

   # Fail CI on HIGH or above findings
   qs-audit scan ./src --fail-on high

   # Enrich a CycloneDX SBOM
   qs-audit sbom sbom.json --output sbom-pqc.json

   # Quick requirements.txt check
   qs-audit requirements requirements.txt

   # NIST compliance report
   qs-audit compliance ./src --format json --output compliance.json
