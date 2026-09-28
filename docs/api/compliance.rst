Compliance (``quantum_safe.compliance``)
==========================================

Profiles that check a configuration against *externally-mandated* cryptographic
requirements, rather than the library's own judgement about what is
appropriate — so that a claim of the form "this configuration meets X" can be
checked instead of asserted.

.. important::

   Every profile in this package reports **parameter selection only**. None of
   them constitutes a FIPS 140-3 / CMVP validation, which is an outcome of
   testing by an accredited laboratory and cannot be produced by
   self-assessment.

CNSA 2.0
--------

The NSA's Commercial National Security Algorithm Suite 2.0 mandates specific
parameter sets — ML-KEM-1024, ML-DSA-87, AES-256, SHA-384/512, and LMS or XMSS
for software/firmware signing — not merely "uses post-quantum algorithms".
This library's own defaults (``ML-KEM-768``, ``ML-DSA-65``) sit *below* the
suite, so ``quantum_safe.compliance.cnsa2`` exists to make that distinction
checkable rather than a footnote.

Quickest path to a compliant configuration:

.. code-block:: python

   from quantum_safe.compliance import cnsa2

   kem    = cnsa2.hybrid_kem()    # X25519 + ML-KEM-1024
   signer = cnsa2.hybrid_sign()   # Ed25519 + ML-DSA-87

Checking an arbitrary configuration:

.. code-block:: python

   from quantum_safe.compliance import cnsa2

   report = cnsa2.report(
       kem="X25519+ML-KEM-768",
       signature="Ed25519+ML-DSA-65",
       hash_algorithm="SHA-256",
   )
   print(report.render())
   # [FAIL] Key establishment ... requires ML-KEM-1024
   # [FAIL] Signatures ... requires ML-DSA-87
   # [FAIL] Hashing ... requires SHA-384 or SHA-512
   # [GAP ] Software/firmware signing (SP 800-208) ...
   # OVERALL: NOT compliant (4 issue(s))

A requirement the library cannot satisfy (SP 800-208 key generation inside a
validated module) counts *against* :attr:`ComplianceReport.compliant` rather
than being silently omitted — an unmet mandate is not neutral.

To fail hard instead of just reporting:

.. code-block:: python

   from quantum_safe.compliance import cnsa2

   cnsa2.enforce(kem="ML-KEM-768", signature="ML-DSA-87")
   # ValueError: configuration is not CNSA 2.0 compliant: ...

.. autofunction:: quantum_safe.compliance.cnsa2.report

.. autofunction:: quantum_safe.compliance.cnsa2.enforce

.. autofunction:: quantum_safe.compliance.cnsa2.hybrid_kem

.. autofunction:: quantum_safe.compliance.cnsa2.hybrid_sign

.. autofunction:: quantum_safe.compliance.cnsa2.check_kem

.. autofunction:: quantum_safe.compliance.cnsa2.check_signature

.. autofunction:: quantum_safe.compliance.cnsa2.check_hash

.. autofunction:: quantum_safe.compliance.cnsa2.lms_available

.. autoclass:: quantum_safe.compliance.cnsa2.ComplianceReport
   :members:
   :show-inheritance:

.. autoclass:: quantum_safe.compliance.cnsa2.CheckResult
   :members:
   :show-inheritance:

.. autoclass:: quantum_safe.compliance.cnsa2.Finding
   :members:
   :show-inheritance:
