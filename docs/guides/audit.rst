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

:class:`~quantum_safe.audit.policy.AuditPolicy` controls which findings
block the CI gate.  Four presets are available:

.. list-table::
   :widths: 20 80
   :header-rows: 1

   * - Preset
     - Behaviour
   * - ``permissive``
     - Never blocks; reports only.
   * - ``transition``
     - Blocks on CRITICAL only.  Allows hybrid during migration.
   * - ``standard``
     - Blocks on HIGH+.  Classical-only is a warning.  **Default.**
   * - ``strict``
     - Blocks on MEDIUM+.  Requires hybrid for all new key usage.

.. code-block:: python

   from quantum_safe.audit import AuditPolicy

   # Use a preset
   policy = AuditPolicy.from_preset("strict")

   # Or configure manually
   policy = AuditPolicy(
       allow_classical_only=False,
       hybrid_required=True,
       block_on_severity="HIGH",
   )

Auditor
-------

:class:`~quantum_safe.audit.auditor.Auditor` exposes the full audit
pipeline for programmatic use:

.. code-block:: python

   from quantum_safe.audit import Auditor, AuditPolicy
   from quantum_safe.migrate import Scanner

   report = Auditor.audit_source("./src", policy=AuditPolicy.from_preset("standard"))
   print(report.summary())

   # Individual finding fields
   for f in report.critical:
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
