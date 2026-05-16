CLI reference
=============

Two CLI tools are installed with the package:

- ``qs-audit`` — scan, audit, SBOM enrichment, compliance reporting
- ``qs-migrate`` — migration scanning, key upgrade, status

qs-audit
--------

``qs-audit scan``
~~~~~~~~~~~~~~~~~

Scan a directory for classical cryptography usage.

.. code-block:: bash

   qs-audit scan <path> [OPTIONS]

   Options:
     --format {text,json,sarif,github}
                          Output format (default: text).
                          github produces GitHub Annotations format.
     --output PATH        Write output to file instead of stdout
     --preset-policy PRESET
                          Policy preset: permissive, transition,
                          standard (default), strict
     --fail-on SEVERITY   Exit 1 when findings at or above this severity
                          exist: critical, high (default), medium, low, never.
                          Use --fail-on never to always exit 0 regardless
                          of findings (useful when running for reporting only).
     --min-severity SEV   Only include findings at or above this severity
                          in the output: critical, high, medium, low (default).
                          Does not affect the exit-code threshold.
     --exclude PATTERN    Glob pattern for paths to skip (repeatable).
                          Matched against both directory names and filenames.
                          Example: --exclude "tests/**" --exclude "*.generated.py"
     --metadata KEY=VALUE Attach arbitrary key/value pairs to the report
                          metadata (repeatable).
                          Example: --metadata commit=$(git rev-parse HEAD)

   Examples:

     # Default scan — text output, exit 1 on HIGH+
     qs-audit scan ./src

     # SARIF for GitHub Code Scanning
     qs-audit scan ./src --format sarif --output audit.sarif

     # JSON report with strict policy
     qs-audit scan ./src --format json --preset-policy strict

     # Only show CRITICAL findings; always exit 0 (report-only mode)
     qs-audit scan ./src --min-severity critical --fail-on never

     # Exclude test and generated files
     qs-audit scan ./src --exclude "tests/**" --exclude "*.generated.py"

     # Annotate report with CI metadata
     qs-audit scan ./src --metadata commit=$(git rev-parse HEAD) \
                         --metadata branch=$(git rev-parse --abbrev-ref HEAD)

``qs-audit sbom``
~~~~~~~~~~~~~~~~~

Enrich a CycloneDX SBOM with PQC-readiness annotations.

.. code-block:: bash

   qs-audit sbom <sbom.json> [OPTIONS]

   Options:
     --output PATH    Write enriched SBOM to file (default: stdout)
     --format {json,summary}
                      json (default) outputs full CycloneDX; summary prints
                      a human-readable table

   Examples:
     qs-audit sbom sbom.json --output sbom-pqc.json
     qs-audit sbom sbom.json --format summary

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
     --format {text,json,sarif}              Output format (default: text)
     --output PATH                           Write output to file
     --min-severity {info,medium,high,critical}
                                             Minimum severity to report
     --fail-on {info,medium,high,critical,never}
                                             Exit 1 at this severity or above

   Examples:
     qs-migrate scan ./src
     qs-migrate scan ./src --format sarif --output migrate.sarif
     qs-migrate scan ./src --min-severity high

``qs-migrate upgrade-key``
~~~~~~~~~~~~~~~~~~~~~~~~~~

Upgrade an existing classical key to a hybrid PQC key.

.. code-block:: bash

   qs-migrate upgrade-key [OPTIONS]

   Options:
     -i, --input PATH          Input PEM key file (required)
     -o, --output PATH         Output PEM file for the upgraded hybrid key (required)
     --target TEXT             Target hybrid algorithm (default: X25519+ML-KEM-768)
     --key-type {kem,sign}     Whether to upgrade a KEM or signing key

``qs-migrate status``
~~~~~~~~~~~~~~~~~~~~~

Show the current migration state for tracked keys.

.. code-block:: bash

   qs-migrate status

Exit codes
----------

Both CLI tools use standard exit codes:

- ``0`` — scan passed (no blocking findings, or ``--fail-on never``)
- ``1`` — scan failed (blocking findings found at or above ``--fail-on`` threshold)
- ``2`` — usage error (invalid arguments)

.. note::

   ``--fail-on never`` overrides **all** exit-code logic, including policy-level
   failures. Use it when you want to run the scanner for reporting purposes
   without failing the CI pipeline.
