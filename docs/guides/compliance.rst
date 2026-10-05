CNSA 2.0 and standards
======================

This page explains what quantum-safe can and cannot tell you about the NSA's Commercial
National Security Algorithm Suite 2.0 (CNSA 2.0), how to read the verdicts it prints, and
how to configure a deployment that selects the CNSA 2.0 parameter sets.

.. important::

   quantum-safe reports **parameter selection only**. CNSA 2.0 compliance for National
   Security Systems runs through FIPS 140-3 validated cryptographic modules, which is an
   outcome of testing by an accredited laboratory. quantum-safe is not a validated module,
   its ACVP results are conformance *evidence* and not a CAVP or CMVP validation, and no
   self-assessment produces a certificate. Nothing here is a statement of compliance.

.. contents:: On this page
   :local:
   :depth: 2

What CNSA 2.0 requires
----------------------

CNSA 2.0 mandates specific *parameter sets*, not merely algorithm families:

.. list-table::
   :header-rows: 1
   :widths: 35 65

   * - Purpose
     - Requirement
   * - Key establishment
     - ML-KEM-1024 (FIPS 203)
   * - Digital signatures
     - ML-DSA-87 (FIPS 204)
   * - Symmetric encryption
     - AES-256
   * - Hashing
     - SHA-384 or SHA-512
   * - Software and firmware signing
     - LMS or XMSS (NIST SP 800-208)

A deployment on ML-KEM-768 uses a FIPS 203 algorithm and is still not CNSA 2.0 aligned.
This library's own defaults (``ML-KEM-768``, ``ML-DSA-65``) sit *below* the suite, which is
why the module exists: so "uses post-quantum algorithms" and "meets the CNSA 2.0 parameter
sets" are different claims you can check.

Reading a report
----------------

.. code-block:: python

   from quantum_safe.compliance import cnsa2

   report = cnsa2.report(
       kem="X25519+ML-KEM-768",
       signature="Ed25519+ML-DSA-65",
       hash_algorithm="SHA-256",
   )
   print(report.render())
   assert not report.compliant

The verdicts:

``PASS``
   The selection meets the requirement.
``FAIL``
   It does not (for example ``ML-KEM-768`` where ``ML-KEM-1024`` is required).
``PART`` (partial)
   The capability is present but is not, on its own, sufficient. A partial counts *against*
   compliance: reporting it as a pass would overstate what the library establishes.
``GAP``
   A mandated capability is absent or not installed (for example LMS without the ``[lms]``
   extra).

``report.compliant`` is true only if every checked requirement passed. An unmet mandate is
never treated as neutral.

Why a hybrid is ``PARTIAL``
---------------------------

A configuration such as ``X25519+ML-KEM-1024`` has the right post-quantum parameter set, so
people often expect it to pass. It is reported ``PARTIAL`` for a reason that comes straight
from NSA's own guidance. The CNSA 2.0 FAQ (December 2024, Ver. 2.1, "Hybrids") says:

   NSA has confidence in CNSA 2.0 algorithms and will not require NSS developers to use
   hybrid certified products for security purposes.

   Do not use a hybrid or other non-standardized QR solution on NSS mission systems except
   for those exceptions NSA specifically recommends.

The only exception the FAQ names is IKEv2, where NSA's profile "will continue the use of
CNSA 1.0 key establishment algorithms, but fortified by key establishment using
ML-KEM-1024". So there is no hybrid that CNSA 2.0 itself calls compliant, and a hybrid is
outside what it prescribes. The post-quantum half being right is necessary, not sufficient.

.. note::

   This is a statement about the *CNSA 2.0 verdict*. Hybrids remain the right choice for
   most other deployments during the transition (see :doc:`choosing`). Reporting one
   ``PARTIAL`` against CNSA 2.0 does not make it unsafe; it means CNSA 2.0 does not bless it.

Configuring for CNSA 2.0 parameters
-----------------------------------

.. code-block:: python

   from quantum_safe.compliance import cnsa2
   from quantum_safe.protocols import Envelope

   kem = cnsa2.pqc_kem()           # a pure ML-KEM-1024 KEM
   signer = cnsa2.pqc_sign()       # a pure ML-DSA-87 signer

   keys = kem.generate_keypair()
   sealed = Envelope.seal(b"classified-adjacent payload", keys.public, aad=b"doc-17")
   assert sealed.version == 2      # envelope v2: pure ML-KEM-1024, HKDF-SHA-384

   assert Envelope.open(sealed, keys.secret, expected_aad=b"doc-17") == b"classified-adjacent payload"

   report = cnsa2.report(kem=kem.algorithm, signature=signer.algorithm,
                         hash_algorithm="SHA-384", include_code_signing=False)
   assert report.compliant         # parameter selection only; see the note at the top

The key-derivation row
~~~~~~~~~~~~~~~~~~~~~~

CNSA 2.0 requires SHA-384 or SHA-512 wherever a hash is used. This library's hybrid
combiner and version-1 envelopes derive keys with HKDF-SHA-256, kept for byte-compatibility
with quantum-safe-ts, so a hybrid selection fails that row. A pure ``ML-KEM-1024``
envelope (**envelope v2**) derives its key with HKDF-SHA-384 and passes it. Because
``Envelope.seal`` chooses the version from the key, using ``cnsa2.pqc_kem()`` is enough.

Guarding a service in CI
~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: python

   from quantum_safe.compliance import cnsa2

   # Default: guards the post-quantum parameter set. Raises for ML-KEM-768 and unknown names;
   # lets a hybrid with an ML-KEM-1024 half pass.
   cnsa2.enforce(kem="ML-KEM-1024", signature="ML-DSA-87")

   # strict=True also refuses anything the report calls PARTIAL, for a hard CI gate.
   try:
       cnsa2.enforce(kem="X25519+ML-KEM-1024", strict=True)
   except ValueError as exc:
       print("refused:", str(exc)[:70], "...")

The same check from the command line (exit status 1 when not compliant):

.. code-block:: bash

   qs-audit cnsa2 --kem ML-KEM-1024 --signature ML-DSA-87 --hash SHA-384 --skip-code-signing

What the profile does not cover
-------------------------------

- **Validation.** FIPS 140-3 validated modules are outside this library's reach.
- **Software and firmware signing.** LMS (RFC 8554) is available through the optional
  ``[lms]`` extra, with a write-ahead state store because LMS is stateful; XMSS is not
  implemented, and SP 800-208 also requires key generation inside a validated module.
- **AES-256 and SHA-384/512 elsewhere in your stack.** The report can check a hash name you
  give it; it cannot see the rest of your system.
- **Protocol profiles.** CNSA 2.0 profiles for TLS, IPsec and others are defined by their
  own documents.

Related standards and how this library relates
----------------------------------------------

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Standard
     - Relationship
   * - FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), FIPS 205 (SLH-DSA)
     - Implemented through liboqs. 225 of 225 runnable NIST ACVP known-answer cases pass
       (conformance evidence, not validation).
   * - NIST SP 800-208 (LMS, XMSS)
     - LMS only, optional extra, write-ahead state store.
   * - RFC 9964 (ML-DSA in JOSE)
     - ``StandardJwt``: tokens and public JWKs (:doc:`protocols`).
   * - TLS hybrid groups (RFC 10024)
     - Not implemented. The hybrid combiner here is a different, HKDF-based construction,
       so quantum-safe envelopes are not readable by TLS implementations.
   * - X-Wing
     - Not implemented in Python (quantum-safe-ts offers it).
   * - CycloneDX 1.6 (CBOM)
     - ``qs-audit cbom`` emits a cryptographic bill of materials.
