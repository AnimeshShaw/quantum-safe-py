CLI reference
=============

Two CLI tools are installed with the package:

- ``qs-audit`` — scan, audit, SBOM enrichment, compliance reporting
- ``qs-migrate`` — migration scanning and status

qs-audit
--------

``qs-audit scan``
~~~~~~~~~~~~~~~~~

Scan a directory for classical cryptography usage.

.. code-block:: bash

   qs-audit scan <path> [OPTIONS]

   Options:
     --format {text,json,sarif}   Output format (default: text)
     --output PATH                Write output to file instead of stdout
     --preset-policy PRESET       Policy preset: permissive, transition,
                                  standard (default), strict
     --fail-on SEVERITY           Exit 1 if findings at or above this severity
                                  exist: critical, high (default), medium, low

   Examples:
     qs-audit scan ./src
     qs-audit scan ./src --format sarif --output audit.sarif
     qs-audit scan ./src --preset-policy strict --fail-on medium

``qs-audit sbom``
~~~~~~~~~~~~~~~~~

Enrich a CycloneDX SBOM with PQC-readiness annotations.

.. code-block:: bash

   qs-audit sbom <sbom.json> [OPTIONS]

   Options:
     --output PATH    Write enriched SBOM to file (default: stdout)

   Examples:
     qs-audit sbom sbom.json --output sbom-pqc.json

``qs-audit requirements``
~~~~~~~~~~~~~~~~~~~~~~~~~

Check a ``requirements.txt`` for PQC-readiness.

.. code-block:: bash

   qs-audit requirements <requirements.txt>

``qs-audit compliance``
~~~~~~~~~~~~~~~~~~~~~~~

Generate a NIST SP 800-208 compliance report.

.. code-block:: bash

   qs-audit compliance <path> [OPTIONS]

   Options:
     --format {text,json}   Output format (default: text)
     --output PATH          Write report to file

   Examples:
     qs-audit compliance ./src --format json --output compliance.json

qs-migrate
----------

``qs-migrate scan``
~~~~~~~~~~~~~~~~~~~

Scan for classical crypto and output a migration-focused report.

.. code-block:: bash

   qs-migrate scan <path> [OPTIONS]

   Options:
     --format {text,json,sarif}   Output format (default: text)
     --output PATH                Write output to file

   Examples:
     qs-migrate scan ./src
     qs-migrate scan ./src --format sarif --output migrate.sarif

``qs-migrate status``
~~~~~~~~~~~~~~~~~~~~~

Show the current migration state for tracked keys.

.. code-block:: bash

   qs-migrate status

Exit codes
----------

Both CLI tools use standard exit codes:

- ``0`` — scan passed (no blocking findings, or ``--fail-on`` threshold not reached)
- ``1`` — scan failed (blocking findings found)
- ``2`` — usage error (invalid arguments)
