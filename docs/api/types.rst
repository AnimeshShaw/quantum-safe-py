Types (``quantum_safe.types``)
==============================

Core data types returned by all key and signature operations.
Raw bytes are never returned directly — every output is a distinct type
that prevents accidental misuse (e.g. passing a ``SharedSecret`` where
a ``CipherText`` is expected).

.. autoclass:: quantum_safe.types.PublicKey
   :members:
   :show-inheritance:

   .. note::

      ``PublicKey.__init__`` validates the raw byte length against known FIPS
      sizes for all non-hybrid algorithms (ML-KEM-512/768/1024, ML-DSA-44/65/87,
      SLH-DSA variants).  Hybrid keys (algorithm names containing ``+``) use a
      length-prefixed composite format and are not validated by this table.

.. autoclass:: quantum_safe.types.SecretKey
   :members:
   :show-inheritance:

   .. note::

      ``SecretKey._raw_bytearray`` returns a fresh mutable ``bytearray`` copy of
      the key bytes for callers (e.g. backends) that need to zero their local copy
      after passing key material to a C library.  Zero it with ``ctypes.memset``
      in a ``try/finally`` block::

         sk_buf = secret_key._raw_bytearray
         try:
             result = c_lib_call(bytes(sk_buf), ...)
         finally:
             import ctypes
             n = len(sk_buf)
             ctypes.memset((ctypes.c_char * n).from_buffer(sk_buf), 0, n)

.. autoclass:: quantum_safe.types.KeyPair
   :members:
   :show-inheritance:

.. autoclass:: quantum_safe.types.MigrationState
   :members:
   :show-inheritance:

.. autoclass:: quantum_safe.types.kem.CipherText
   :members:
   :show-inheritance:

.. autoclass:: quantum_safe.types.kem.HybridCipherText
   :members:
   :show-inheritance:

.. autoclass:: quantum_safe.types.kem.SharedSecret
   :members:
   :show-inheritance:

.. autoclass:: quantum_safe.types.SignedMessage
   :members:
   :show-inheritance:

.. autoclass:: quantum_safe.types.signatures.HybridSignature
   :members:
   :show-inheritance:

Utilities
---------

.. autofunction:: quantum_safe.types.keys.generate_nonce

.. note::

   ``generate_nonce(length)`` emits a ``UserWarning`` if ``length < 12``,
   since 12 bytes is the minimum nonce size for AEAD ciphers such as AES-GCM.
   The default of 32 bytes is always safe.
