Migration (``quantum_safe.migrate``)
=====================================

Tools for scanning codebases and upgrading classical keys to hybrid PQC.

Scanner
-------

.. autoclass:: quantum_safe.migrate.scanner.Scanner
   :members:
   :show-inheritance:

.. autoclass:: quantum_safe.migrate.scanner.ScanReport
   :members:
   :show-inheritance:

.. autoclass:: quantum_safe.migrate.scanner.Finding
   :members:
   :show-inheritance:

Upgrader
--------

.. autoclass:: quantum_safe.migrate.upgrader.Upgrader
   :members:
   :show-inheritance:

.. autoclass:: quantum_safe.migrate.upgrader.UpgradeResult
   :members:
   :show-inheritance:

Migration state
---------------

.. autoclass:: quantum_safe.migrate.state.MigrationStateManager
   :members:
   :show-inheritance:

Shims
-----

.. autoclass:: quantum_safe.migrate.shims.FernetShim
   :members:
   :show-inheritance:

.. autoclass:: quantum_safe.migrate.shims.JWTShim
   :members:
   :show-inheritance:
