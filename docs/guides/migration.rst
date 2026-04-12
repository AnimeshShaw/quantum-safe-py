Migration tooling
=================

The migration module helps you move an existing codebase from classical
cryptography to hybrid PQC without breaking existing integrations.

Scanning for classical crypto
------------------------------

:class:`~quantum_safe.migrate.scanner.Scanner` uses Python AST analysis
to detect classical-only cryptographic usage.  It ships 14 built-in rules
covering:

- RSA and ECDSA key generation and signing
- AES-ECB usage
- MD5 and SHA-1 digest usage
- ``secrets.token_bytes`` used as a key without KDF
- Hard-coded cryptographic constants
- Fernet (symmetric encryption without forward secrecy)

.. code-block:: python

   from quantum_safe.migrate import Scanner

   report = Scanner.scan_directory("./src")
   print(report.summary())
   # Scanned 42 files in './src': 2 CRITICAL, 5 HIGH, 3 MEDIUM

   for finding in report.critical + report.high:
       print(f"{finding.file}:{finding.line} [{finding.rule_id}]")
       print(f"  {finding.message}")
       print(f"  Fix: {finding.fix_hint}")

   # Exit 1 in CI if blocking findings exist
   if report.has_blocking_findings:
       import sys; sys.exit(1)

SARIF output (GitHub Code Scanning):

.. code-block:: python

   report = Scanner.scan_directory("./src")
   sarif  = report.to_sarif()
   with open("migrate.sarif", "w") as f:
       import json; json.dump(sarif, f)

Upgrading an existing key to hybrid
-------------------------------------

:class:`~quantum_safe.migrate.upgrader.Upgrader` takes an existing
classical key and produces a hybrid keypair.  Old senders that still
use the classical-only public key can still encrypt to the new public key.

.. code-block:: python

   from quantum_safe.migrate import Upgrader

   result = Upgrader.upgrade_kem_key(
       classical_secret_bytes=x25519_private_bytes,
       classical_public_bytes=x25519_public_bytes,
       classical_algorithm="X25519",
       target_pqc="ML-KEM-768",
   )

   new_kp = result.new_keypair
   print(new_kp.public.algorithm)      # "X25519+ML-KEM-768"
   print(result.notes)                  # human-readable upgrade notes

Tracking migration progress
----------------------------

:class:`~quantum_safe.migrate.state.MigrationStateManager` maintains
a per-key state machine tracking where each key sits in the migration path:

- ``CLASSICAL_ONLY`` → ``HYBRID_TRANSITION`` → ``PQC_PREFERRED`` → ``PQC_ONLY``

.. note::

   **Thread safety**: ``transition()`` holds a per-key ``threading.Lock`` across
   the read-check-write critical section, so concurrent in-process calls for the
   same ``key_id`` are safe.  For multi-process deployments (multiple workers
   sharing a Redis or database store) you must additionally hold an external
   distributed lock (e.g. Redis ``SETNX``, a ``SELECT … FOR UPDATE`` row lock)
   on the ``key_id`` before calling ``transition()``.

.. code-block:: python

   from quantum_safe.migrate import MigrationStateManager
   from quantum_safe.types import MigrationState

   store = {}  # replace with Redis / DynamoDB / Postgres
   mgr   = MigrationStateManager(store)

   mgr.transition(
       key_id="user-123",
       from_state=MigrationState.CLASSICAL_ONLY,
       to_state=MigrationState.HYBRID_TRANSITION,
       algorithm="X25519+ML-KEM-768",
       actor="key-rotation-v2",
   )

   progress = mgr.migration_progress()
   print(progress)
   # {'classical_only': 847, 'hybrid_transition': 152, 'pqc_only': 1}

Drop-in shims
-------------

:class:`~quantum_safe.migrate.shims.FernetShim` and
:class:`~quantum_safe.migrate.shims.JWTShim` are drop-in replacements for
``cryptography.fernet.Fernet`` and ``PyJWT``.  They log every usage so
you can identify callers before migrating them:

.. code-block:: python

   from quantum_safe.migrate.shims import FernetShim

   # Drop-in for cryptography.fernet.Fernet
   f   = FernetShim(key)
   tok = f.encrypt(b"payload")         # logs: "FernetShim.encrypt called from ..."
   msg = f.decrypt(tok)

   from quantum_safe.migrate.shims import JWTShim

   tok    = JWTShim.encode({"sub": "1"}, secret, algorithm="HS256")
   claims = JWTShim.decode(tok, secret, algorithms=["HS256"])

CLI
---

.. code-block:: bash

   # Scan a codebase
   qs-migrate scan ./src --format sarif --output migrate.sarif

   # Check migration progress
   qs-migrate status
