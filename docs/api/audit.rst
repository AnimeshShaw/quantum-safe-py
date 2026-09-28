Audit (``quantum_safe.audit``)
===============================

Compliance auditing, NIST mapping, and SBOM enrichment.

Auditor
-------

.. autoclass:: quantum_safe.audit.auditor.Auditor
   :members:
   :show-inheritance:

Policy
------

.. autoclass:: quantum_safe.audit.policy.AuditPolicy
   :members:
   :show-inheritance:

NIST compliance
---------------

.. autoclass:: quantum_safe.audit.compliance.NISTComplianceChecker
   :members:
   :show-inheritance:

.. autoclass:: quantum_safe.audit.compliance.ComplianceReport
   :members:
   :show-inheritance:

SBOM enrichment
---------------

.. autoclass:: quantum_safe.audit.sbom.SBOMEnricher
   :members:
   :show-inheritance:

.. autoclass:: quantum_safe.audit.sbom.ComponentAssessment
   :members:
   :show-inheritance:

Cryptographic Bill of Materials (CBOM)
---------------------------------------

CycloneDX 1.6 ``cryptographic-asset`` output. Separates *detected* algorithms
(one component per file:line occurrence, from a :class:`~quantum_safe.migrate.scanner.ScanReport`)
from *provided* algorithms (the post-quantum primitives this library offers,
with NIST quantum security levels attached).

This is an inventory, not a compliance verdict — see
:doc:`/api/compliance` for CNSA 2.0 parameter-set checking, and note that
neither is a FIPS 140-3 validation.

.. code-block:: python

   from quantum_safe.audit.cbom import build_cbom, to_json
   from quantum_safe.migrate.scanner import Scanner

   scan = Scanner.scan_directory("./src")
   cbom = build_cbom(scan, application_name="my-service")
   print(to_json(cbom))

.. autofunction:: quantum_safe.audit.cbom.build_cbom

.. autofunction:: quantum_safe.audit.cbom.to_json

.. autoclass:: quantum_safe.audit.cbom.CryptoAssetSpec
   :members:
   :show-inheritance:
