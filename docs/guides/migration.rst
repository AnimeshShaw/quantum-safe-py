Migration tooling
=================

The migration module helps you move an existing codebase from classical
cryptography to hybrid PQC without breaking existing integrations.

Scanning for classical crypto
------------------------------

:class:`~quantum_safe.migrate.scanner.Scanner` uses Python AST analysis
to detect classical-only cryptographic usage.  It ships 14 built-in rules
covering:

- RSA and ECDSA key generation and signing (``cryptography``, ``pycryptodome``)
- AES-ECB and 3DES usage
- MD5 and SHA-1 digest usage — via both the ``cryptography`` library
  (``hashes.MD5``, ``hashes.SHA1``) and the stdlib ``hashlib`` module
  (``hashlib.md5()``, ``hashlib.sha1()``, ``hashlib.sha224()``)
- Classical JWT algorithm identifiers (``RS256``, ``ES256``, etc.)
- Hard-coded cryptographic constants

.. note::

   The scanner is **Python-only**: it walks ``.py`` source files using the
   ``ast`` module.  JavaScript, Go, Java, and configuration files (nginx,
   openssl.cnf) are not yet supported.

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
classical key and produces a hybrid keypair that contains it.  The hybrid
public key is a new format (``u16(len(classical)) || classical || pqc``) that
classical-only software cannot parse, so the upgrade is not backward
compatible on its own: classical-only senders keep using the original key,
which you continue to publish during the transition.

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

   **Concurrency**: give the manager a store with a
   ``compare_and_set(key, expected, value) -> bool`` method (``expected=None``
   means "the key must not exist") and ``transition()`` commits through one
   atomic operation, so it is safe across any number of processes and hosts
   sharing the store with **no external lock**: exactly one concurrent writer
   wins and the others get a stale-state ``ValueError``.
   :class:`~quantum_safe.migrate.state.MemoryMigrationStore` is the in-process
   reference; for Redis use ``WATCH``/``MULTI`` or a Lua script, for Postgres
   ``UPDATE ... WHERE value = expected`` (and ``INSERT ... ON CONFLICT DO
   NOTHING`` for absent), for DynamoDB a ``ConditionExpression``.
   ``manager.cross_process_safe`` tells you which mode you are in.

   With a plain dict (no ``compare_and_set``) ``transition()`` holds a per-key
   ``threading.Lock``, which covers threads in **one process only**: with several
   workers sharing a store, two of them can both pass the read-check and both
   write.  In a test with 16 managers racing on one plain dict, every one of 300
   races produced more than one winner; with a compare-and-set store, none did.
   Hold an external distributed lock (Redis ``SETNX``, a ``SELECT … FOR UPDATE``
   row lock) on the ``key_id`` in that case.

   **Layout and durability**: the layout is unchanged (``<key_id>_current`` and
   ``<key_id>_history``).  With compare-and-set the history entry is the single
   thing committed atomically and is authoritative; ``_current`` is a derived
   copy written right after, so a crash in between leaves it one record behind
   and the manager reads the state from the history.  Without it, the history is
   written first and then ``_current`` (a crash between them leaves ``_current``
   behind the audit log).

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
