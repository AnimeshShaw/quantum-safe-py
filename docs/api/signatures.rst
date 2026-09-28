Signatures (``quantum_safe.signatures``)
=========================================

Digital signature operations.  The high-level entry point is
:class:`~quantum_safe.signatures.hybrid.HybridSign`.

.. autoclass:: quantum_safe.signatures.hybrid.HybridSign
   :members:
   :show-inheritance:

.. autoclass:: quantum_safe.signatures.core.Sign
   :members:
   :show-inheritance:

Algorithm registry
------------------

.. autofunction:: quantum_safe.signatures.algorithms.get_algorithm_spec

.. autofunction:: quantum_safe.signatures.algorithms.canonical_hybrid_name

.. autofunction:: quantum_safe.signatures.algorithms.parse_hybrid_name

.. autofunction:: quantum_safe.signatures.algorithms.validate_hybrid_combination


LMS stateful signatures (``quantum_safe.signatures.stateful``)
----------------------------------------------------------------

.. warning::

   LMS is **stateful**. Signing twice at the same one-time-key index does not
   fail or warn — it produces two signatures that both verify, from which an
   attacker can forge further signatures, compromising every signature ever
   made under that key. This is easy to trigger by accident: restoring a VM
   snapshot, a database backup, or a container image; copying a key file to a
   second signer; crashing after signing but before persisting the advanced
   index. **Read the module docstring in full before using this in
   production.**

Optional support for LMS (RFC 8554), required by CNSA 2.0 for software and
firmware signing (SP 800-208) and not available through liboqs. Requires the
``[lms]`` extra (wraps `pyhsslms <https://github.com/russhousley/pyhsslms>`_,
maintained by an RFC 8554 co-author).

The wrapper refuses to make the unsafe path convenient:

* **Write-ahead index reservation** — the advanced index is persisted through
  a caller-supplied :class:`~quantum_safe.signatures.stateful.LmsStateStore`
  *before* the signature is produced. Crashing between the two costs one
  unused index; the reverse order costs the key, so it is not offered.
* **Rewind detection** — a key presented at an index at or below one already
  issued raises :class:`~quantum_safe.signatures.stateful.IndexReuseError`
  instead of signing.
* **No durable default store** — :class:`~quantum_safe.signatures.stateful.InMemoryLmsStateStore`
  is for tests only and says so in its name; a caller must supply real
  persistence (a transactional database, or an fsync'd + locked file).

.. code-block:: python

   from quantum_safe.signatures.stateful import LmsSigner, verify

   # `store` must be a durable LmsStateStore implementation you control —
   # never the in-memory one, outside tests.
   signer = LmsSigner.generate("firmware-signing-key-2027", store, tree_height=10)
   sig = signer.sign(firmware_image)
   assert verify(signer.public_key(), firmware_image, sig)

   # Loading an existing key re-checks the state store, so a key restored
   # from a stale backup is refused rather than silently reused:
   signer = LmsSigner.load("firmware-signing-key-2027", serialised_key, store)

SP 800-208 also requires key generation to occur inside a validated
cryptographic module — a property of the deployment, not of this library.
Providing the algorithm does not by itself satisfy SP 800-208.

.. autoclass:: quantum_safe.signatures.stateful.LmsSigner
   :members:
   :show-inheritance:

.. autofunction:: quantum_safe.signatures.stateful.verify

.. autoclass:: quantum_safe.signatures.stateful.LmsStateStore
   :members:
   :show-inheritance:

.. autoclass:: quantum_safe.signatures.stateful.InMemoryLmsStateStore
   :members:
   :show-inheritance:

.. autoclass:: quantum_safe.signatures.stateful.LmsKeyInfo
   :members:
   :show-inheritance:

.. autoclass:: quantum_safe.signatures.stateful.StatefulSignatureError
   :show-inheritance:

.. autoclass:: quantum_safe.signatures.stateful.KeyExhaustedError
   :show-inheritance:

.. autoclass:: quantum_safe.signatures.stateful.IndexReuseError
   :show-inheritance:

.. autoclass:: quantum_safe.signatures.stateful.StatePersistenceError
   :show-inheritance:
