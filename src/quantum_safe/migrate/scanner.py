"""
quantum_safe.migrate.scanner
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

AST-based scanner that finds classical cryptography usage in Python codebases.

The scanner walks Python source files, parses them with the stdlib `ast`
module, and matches patterns against a catalogue of known-classical APIs.
The output is a structured ScanReport that can be serialized to SARIF (for
GitHub Code Scanning / GitLab SAST), plain JSON, or a human-readable table.

Why AST and not grep?
    grep finds string literals, not actual usage. A grep for "RSA" would
    miss `from cryptography.hazmat.primitives.asymmetric import rsa; rsa.generate_private_key(...)`.
    The AST walk sees the import, resolves the alias, and matches the call.
    This reduces both false positives (comments mentioning RSA) and false
    negatives (aliased imports).

Severity model
    CRITICAL:  RSA < 2048 bits, or key material directly in source
    HIGH:      RSA >= 2048, ECDSA/ECDH with any curve, DSA, Ed25519-only signing
    MEDIUM:    AES-128, SHA-1, MD5, PBKDF2 with low iterations
    INFO:      Classical-safe usage that will need migration eventually
               (e.g. AES-256 is fine today but note it for inventory)

What we scan for
    - Imports of classical crypto libraries (cryptography, pycryptodome, pyca)
    - Direct key generation calls (rsa.generate_private_key, etc.)
    - Hardcoded key sizes below thresholds
    - Algorithm string literals ("RS256", "HS256", "AES-128-CBC")
    - JWT algorithm identifiers in string constants

Limitations
    - Dynamic imports (importlib.import_module) are not resolved.
    - Obfuscated code or eval() are not analyzed.
    - Third-party library internals are not followed.
    - Only Python files are supported in this version. TypeScript/Rust
      scanning is planned for v0.2.
"""

from __future__ import annotations

import ast
import fnmatch
import json
import os
import pathlib
from collections.abc import Iterator
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any


class Severity(IntEnum):
    """Finding severity levels, ordered so higher = worse."""
    INFO = 0
    MEDIUM = 1
    HIGH = 2
    CRITICAL = 3


@dataclass
class Finding:
    """A single classical crypto usage finding.

    Attributes:
        file:       Absolute or relative path to the source file.
        line:       1-based line number.
        col:        1-based column number.
        severity:   Severity level.
        rule_id:    Short machine-readable rule identifier, e.g. "QS001".
        message:    Human-readable description.
        snippet:    The offending source line, stripped of leading whitespace.
        fix_hint:   Optional suggestion for how to fix the issue.
    """

    file: str
    line: int
    col: int
    severity: Severity
    rule_id: str
    message: str
    snippet: str = ""
    fix_hint: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "file":     self.file,
            "line":     self.line,
            "col":      self.col,
            "severity": self.severity.name,
            "rule_id":  self.rule_id,
            "message":  self.message,
            "snippet":  self.snippet,
            "fix_hint": self.fix_hint,
        }

    def __str__(self) -> str:
        sev = self.severity.name.ljust(8)
        return f"[{sev}] {self.file}:{self.line}:{self.col}  {self.rule_id}  {self.message}"


@dataclass
class ScanReport:
    """Aggregated results from scanning one or more files/directories.

    Attributes:
        root:       The directory or file that was scanned.
        files_scanned:  Number of Python files analyzed.
        findings:   All findings, sorted by (file, line).
        errors:     Files that could not be parsed (syntax errors, permission issues).
    """

    root: str
    files_scanned: int = 0
    findings: list[Finding] = field(default_factory=list)
    errors: list[dict[str, str]] = field(default_factory=list)

    # ------------------------------------------------------------------
    # Convenience accessors
    # ------------------------------------------------------------------

    @property
    def critical(self) -> list[Finding]:
        return [f for f in self.findings if f.severity == Severity.CRITICAL]

    @property
    def high(self) -> list[Finding]:
        return [f for f in self.findings if f.severity == Severity.HIGH]

    @property
    def medium(self) -> list[Finding]:
        return [f for f in self.findings if f.severity == Severity.MEDIUM]

    @property
    def info(self) -> list[Finding]:
        return [f for f in self.findings if f.severity == Severity.INFO]

    @property
    def has_blocking_findings(self) -> bool:
        """True if there are any HIGH or CRITICAL findings.

        This is the condition that should cause a CI gate to fail.
        """
        return any(f.severity >= Severity.HIGH for f in self.findings)

    def summary(self) -> str:
        """One-line summary for logging."""
        parts = []
        if self.critical:
            parts.append(f"{len(self.critical)} CRITICAL")
        if self.high:
            parts.append(f"{len(self.high)} HIGH")
        if self.medium:
            parts.append(f"{len(self.medium)} MEDIUM")
        if self.info:
            parts.append(f"{len(self.info)} INFO")
        if not parts:
            parts.append("no findings")
        return (
            f"Scanned {self.files_scanned} files in '{self.root}': "
            + ", ".join(parts)
        )

    # ------------------------------------------------------------------
    # Serialization
    # ------------------------------------------------------------------

    def to_json(self, indent: int = 2) -> str:
        """Serialize to JSON."""
        return json.dumps(
            {
                "root":          self.root,
                "files_scanned": self.files_scanned,
                "summary":       self.summary(),
                "findings":      [f.to_dict() for f in self.findings],
                "errors":        self.errors,
            },
            indent=indent,
        )

    def to_sarif(self) -> dict[str, Any]:
        """Produce a SARIF 2.1.0 document for GitHub Code Scanning / GitLab SAST.

        The result can be written to a file and uploaded as a SARIF artifact.
        See: https://docs.github.com/en/code-security/code-scanning/sarif-schema
        """
        # Build the rules list from distinct rule_ids
        seen_rules: dict[str, Finding] = {}
        for f in self.findings:
            if f.rule_id not in seen_rules:
                seen_rules[f.rule_id] = f

        rules = [
            {
                "id":   rule_id,
                "name": rule_id,
                "shortDescription": {"text": f.message},
                "defaultConfiguration": {
                    "level": _sarif_level(f.severity)
                },
                "helpUri": "https://quantum-safe-py.readthedocs.io/en/latest/guides/audit.html",
            }
            for rule_id, f in seen_rules.items()
        ]

        results = []
        for f in self.findings:
            results.append({
                "ruleId":  f.rule_id,
                "message": {"text": f.message},
                "level":   _sarif_level(f.severity),
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": f.file},
                            "region": {
                                "startLine":   f.line,
                                "startColumn": f.col,
                            },
                        }
                    }
                ],
                "fixes": [
                    {
                        "description": {"text": f.fix_hint},
                    }
                ] if f.fix_hint else [],
            })

        return {
            "$schema":  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version":  "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name":    "qs-audit",
                            "version": "0.1.0",
                            "rules":   rules,
                        }
                    },
                    "results": results,
                }
            ],
        }


def _sarif_level(severity: Severity) -> str:
    return {
        Severity.CRITICAL: "error",
        Severity.HIGH:     "error",
        Severity.MEDIUM:   "warning",
        Severity.INFO:     "note",
    }[severity]


# ---------------------------------------------------------------------------
# Rule catalogue
# ---------------------------------------------------------------------------
# Each rule is a dict with:
#   id:       Short rule ID, e.g. "QS001"
#   severity: Severity level
#   message:  Template (may contain {detail})
#   fix_hint: Replacement suggestion
#   match:    Callable(node, aliases) -> bool | str (False = no match, str = detail)

# Tracks imports: maps alias -> canonical module path
# e.g. "rsa" -> "cryptography.hazmat.primitives.asymmetric.rsa"
_Aliases = dict[str, str]


def _is_attr_call(node: ast.AST, aliases: _Aliases, *path: str) -> bool:
    """Return True if `node` is a call of the form a.b.c(*args).

    path is the expected attribute chain, e.g. ("rsa", "generate_private_key").
    The first element is matched against the aliases dict.
    """
    if not isinstance(node, ast.Call):
        return False
    func = node.func
    if len(path) == 1:
        return (
            isinstance(func, ast.Name)
            and aliases.get(func.id, func.id) == path[0]
        )
    if len(path) == 2:
        return (
            isinstance(func, ast.Attribute)
            and func.attr == path[1]
            and isinstance(func.value, ast.Name)
            and aliases.get(func.value.id, func.value.id).endswith(path[0])
        )
    return False


def _string_value(node: ast.AST) -> str | None:
    """Extract string value from an ast.Constant node."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


# Classical API patterns that indicate non-quantum-safe usage
_RULES: list[dict[str, Any]] = [
    # ---- RSA -------------------------------------------------------
    {
        "id":       "QS001",
        "severity": Severity.HIGH,
        "message":  "RSA key generation detected - RSA is not quantum-safe",
        "fix_hint": "Replace with HybridKEM() for key exchange or HybridSign() for signatures",
        "imports":  {"cryptography.hazmat.primitives.asymmetric.rsa"},
        "calls":    {("rsa", "generate_private_key")},
    },
    {
        "id":       "QS002",
        "severity": Severity.HIGH,
        "message":  "RSA PKCS1v15 padding detected - not quantum-safe",
        "fix_hint": "Replace RSA encryption with Envelope.seal() / Envelope.open()",
        "imports":  {"cryptography.hazmat.primitives.asymmetric.padding"},
        "calls":    {("padding", "PKCS1v15")},
    },
    {
        "id":       "QS003",
        "severity": Severity.HIGH,
        "message":  "RSA-OAEP encryption detected - not quantum-safe",
        "fix_hint": "Replace with Envelope.seal() which uses HybridKEM + AES-256-GCM",
        "imports":  {"cryptography.hazmat.primitives.asymmetric.padding"},
        "calls":    {("padding", "OAEP")},
    },
    # ---- ECDSA / ECDH ---------------------------------------------
    {
        "id":       "QS010",
        "severity": Severity.HIGH,
        "message":  "ECDSA key generation detected - not quantum-safe",
        "fix_hint": "Replace with HybridSign() for signatures",
        "imports":  {"cryptography.hazmat.primitives.asymmetric.ec"},
        "calls":    {("ec", "generate_private_key")},
    },
    {
        "id":       "QS011",
        "severity": Severity.HIGH,
        "message":  "ECDH key exchange detected - not quantum-safe",
        "fix_hint": "Replace with HybridKEM() for key exchange",
        "imports":  {"cryptography.hazmat.primitives.asymmetric.ec"},
        "calls":    {("ec", "ECDH")},
    },
    # ---- DSA -------------------------------------------------------
    {
        "id":       "QS015",
        "severity": Severity.CRITICAL,
        "message":  "DSA key generation detected - not quantum-safe and deprecated",
        "fix_hint": "Replace with HybridSign() (ML-DSA-65 + Ed25519)",
        "imports":  {"cryptography.hazmat.primitives.asymmetric.dsa"},
        "calls":    {("dsa", "generate_private_key")},
    },
    # ---- DH (classical Diffie-Hellman) ----------------------------
    {
        "id":       "QS016",
        "severity": Severity.HIGH,
        "message":  "Classical DH key generation detected - not quantum-safe",
        "fix_hint": "Replace with HybridKEM()",
        "imports":  {"cryptography.hazmat.primitives.asymmetric.dh"},
        "calls":    {("dh", "generate_parameters")},
    },
    # ---- Weak symmetric -------------------------------------------
    {
        "id":       "QS020",
        "severity": Severity.MEDIUM,
        "message":  "AES-128 detected - consider upgrading to AES-256",
        "fix_hint": "Use AES-256-GCM. Envelope.seal() uses AES-256-GCM by default.",
        "imports":  set(),
        "string_patterns": {"AES-128", "AES128"},
    },
    {
        "id":       "QS021",
        "severity": Severity.MEDIUM,
        "message":  "3DES / TripleDES detected - deprecated and not quantum-safe",
        "fix_hint": "Replace with AES-256-GCM",
        "imports":  {"cryptography.hazmat.primitives.ciphers.algorithms"},
        "calls":    {("algorithms", "TripleDES")},
        "string_patterns": {"3DES", "TripleDES", "DES3"},
    },
    # ---- Weak hash ------------------------------------------------
    {
        "id":       "QS030",
        "severity": Severity.MEDIUM,
        "message":  "SHA-1 detected - cryptographically broken",
        "fix_hint": "Replace with SHA-256 or SHA-3",
        "imports":  {"cryptography.hazmat.primitives.hashes", "hashlib"},
        "calls":    {("hashes", "SHA1"), ("hashlib", "sha1"), ("hashlib", "sha224")},
        "string_patterns": {"SHA1", "SHA-1"},
    },
    {
        "id":       "QS031",
        "severity": Severity.CRITICAL,
        "message":  "MD5 detected - cryptographically broken",
        "fix_hint": "Replace with SHA-256 or BLAKE2b",
        "imports":  {"cryptography.hazmat.primitives.hashes", "hashlib"},
        "calls":    {("hashes", "MD5"), ("hashlib", "md5")},
        "string_patterns": {"MD5"},
    },
    # hashlib.new("sha1") / hashlib.new("md5") are caught by string_patterns above
    # since the algorithm name is a string literal passed to hashlib.new().
    # ---- JWT algorithm identifiers --------------------------------
    {
        "id":       "QS040",
        "severity": Severity.HIGH,
        "message":  "Classical JWT algorithm '{detail}' detected",
        "fix_hint": "Use JWTSigner from quantum_safe.protocols.jwt with ML-DSA-65",
        "imports":  set(),
        "string_patterns": {"RS256", "RS384", "RS512", "ES256", "ES384",
                             "PS256", "PS384", "PS512"},
    },
    # ---- pycryptodome / pycrypto -----------------------------------
    {
        "id":       "QS050",
        "severity": Severity.HIGH,
        "message":  "pycryptodome RSA usage detected - not quantum-safe",
        "fix_hint": "Replace with quantum_safe.HybridKEM or HybridSign",
        "imports":  {"Crypto.PublicKey.RSA", "Cryptodome.PublicKey.RSA"},
        "calls":    set(),
    },
    {
        "id":       "QS051",
        "severity": Severity.HIGH,
        "message":  "pycryptodome ECC usage detected - not quantum-safe",
        "fix_hint": "Replace with quantum_safe.HybridSign",
        "imports":  {"Crypto.PublicKey.ECC", "Cryptodome.PublicKey.ECC"},
        "calls":    set(),
    },
]

# Build fast lookup: module_path -> [rules that trigger on import]
_IMPORT_RULE_MAP: dict[str, list[dict[str, Any]]] = {}
for _rule in _RULES:
    for _imp in _rule.get("imports", set()):
        _IMPORT_RULE_MAP.setdefault(_imp, []).append(_rule)


# ---------------------------------------------------------------------------
# AST visitor
# ---------------------------------------------------------------------------


class _ClassicalCryptoVisitor(ast.NodeVisitor):
    """Walks an AST and collects classical crypto usage findings."""

    def __init__(self, filename: str, source_lines: list[str]) -> None:
        self._filename = filename
        self._lines = source_lines
        self.findings: list[Finding] = []

        # alias -> canonical module path (built from imports)
        self._module_aliases: _Aliases = {}
        # alias -> set of attribute names imported from a module
        self._from_imports: dict[str, str] = {}
        # Which rules are triggered by imports we've seen
        self._active_rules: list[dict[str, Any]] = []

    def _snippet(self, lineno: int) -> str:
        if 1 <= lineno <= len(self._lines):
            return self._lines[lineno - 1].strip()
        return ""

    def _add(
        self,
        node: ast.AST,
        rule: dict[str, Any],
        detail: str = "",
    ) -> None:
        lineno = getattr(node, "lineno", 0)
        col = getattr(node, "col_offset", 0) + 1  # 1-based
        message = rule["message"].replace("{detail}", detail) if detail else rule["message"]
        self.findings.append(
            Finding(
                file=self._filename,
                line=lineno,
                col=col,
                severity=rule["severity"],
                rule_id=rule["id"],
                message=message,
                snippet=self._snippet(lineno),
                fix_hint=rule.get("fix_hint", ""),
            )
        )

    # ------------------------------------------------------------------
    # Import tracking
    # ------------------------------------------------------------------

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            name = alias.asname or alias.name.split(".")[0]
            self._module_aliases[name] = alias.name
            # Check import-triggered rules
            for rule in _IMPORT_RULE_MAP.get(alias.name, []):
                if rule not in self._active_rules:
                    self._active_rules.append(rule)
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        module = node.module or ""
        for alias in node.names:
            local_name = alias.asname or alias.name
            full_path = f"{module}.{alias.name}" if module else alias.name
            self._from_imports[local_name] = full_path
            # Track module alias for call matching
            self._module_aliases[local_name] = full_path
            # Activate rules: check full_path (module.name) and module itself
            for trigger_mod, rules in _IMPORT_RULE_MAP.items():
                if (
                    full_path == trigger_mod
                    or module == trigger_mod
                    or module.startswith(trigger_mod + ".")
                    or trigger_mod.startswith(module + ".")
                ):
                    for rule in rules:
                        if rule not in self._active_rules:
                            self._active_rules.append(rule)
        self.generic_visit(node)

    # ------------------------------------------------------------------
    # String constant scanning
    # ------------------------------------------------------------------

    def visit_Constant(self, node: ast.Constant) -> None:
        """Scan string literals for known classical algorithm names."""
        if not isinstance(node.value, str):
            return
        val = node.value.strip()
        for rule in _RULES:
            for pattern in rule.get("string_patterns", set()):
                if pattern in val:
                    self._add(node, rule, detail=pattern)
                    break  # one match per rule per node
        self.generic_visit(node)

    # ------------------------------------------------------------------
    # Call scanning
    # ------------------------------------------------------------------

    def visit_Call(self, node: ast.Call) -> None:
        """Check if this call matches any active rule's call patterns."""
        for rule in self._active_rules:
            for call_path in rule.get("calls", set()):
                if self._matches_call(node, call_path):
                    self._add(node, rule)
                    break
        self.generic_visit(node)

    def _matches_call(self, node: ast.Call, call_path: tuple[str, ...]) -> bool:
        """Check if a Call node matches a (module, function) pattern."""
        module_name, func_name = call_path
        func = node.func
        if isinstance(func, ast.Attribute):
            if func.attr != func_name:
                return False
            if isinstance(func.value, ast.Name):
                resolved = self._module_aliases.get(func.value.id, func.value.id)
                return resolved.endswith(module_name)
        elif isinstance(func, ast.Name):
            resolved = self._module_aliases.get(func.id, func.id)
            return resolved.endswith(func_name)
        return False


# ---------------------------------------------------------------------------
# Public scanner interface
# ---------------------------------------------------------------------------


class Scanner:
    """Scans Python source files for classical cryptography usage.

    Usage::

        report = Scanner.scan_directory("./src")
        print(report.summary())

        if report.has_blocking_findings:
            for f in report.high + report.critical:
                print(f)
            sys.exit(1)
    """

    @classmethod
    def scan_file(cls, filepath: str | pathlib.Path) -> ScanReport:
        """Scan a single Python file.

        Args:
            filepath: Path to a .py file.

        Returns:
            ScanReport with findings for this file.
        """
        filepath = str(filepath)
        report = ScanReport(root=filepath)
        cls._scan_one(filepath, report)
        report.findings.sort(key=lambda f: (f.file, f.line, f.col))
        return report

    @classmethod
    def scan_directory(
        cls,
        directory: str | pathlib.Path,
        exclude: list[str] | None = None,
        max_file_size_kb: int = 512,
    ) -> ScanReport:
        """Recursively scan a directory for classical crypto usage.

        Args:
            directory:          Root directory to scan.
            exclude:            Glob patterns to exclude.
                                Default excludes: .git, __pycache__, .venv, node_modules.
            max_file_size_kb:   Skip files larger than this
                                (avoid scanning minified/generated code).

        Returns:
            ScanReport with aggregated findings.
        """
        directory = pathlib.Path(directory)
        if not directory.exists():
            raise FileNotFoundError(f"Directory not found: {directory}")

        default_excludes = {
            ".git", "__pycache__", ".venv", "venv", "node_modules",
            ".mypy_cache", ".pytest_cache", "dist", "build", "*.egg-info",
        }
        excluded = set(exclude or []) | default_excludes

        report = ScanReport(root=str(directory))

        for py_file in cls._iter_python_files(directory, excluded, max_file_size_kb):
            cls._scan_one(str(py_file), report)

        report.findings.sort(key=lambda f: (f.file, f.line, f.col))
        return report

    @classmethod
    def scan_source(
        cls, source: str, filename: str = "<string>"
    ) -> ScanReport:
        """Scan a source string directly (useful for testing or inline analysis)."""
        report = ScanReport(root=filename)
        cls._scan_source_text(source, filename, report)
        return report

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    @staticmethod
    def _iter_python_files(
        root: pathlib.Path,
        excluded: set[str],
        max_kb: int,
    ) -> Iterator[pathlib.Path]:
        """Yield .py files under root, respecting exclusions."""
        for dirpath, dirnames, filenames in os.walk(root):
            # Prune excluded directories in-place
            dirnames[:] = [
                d for d in dirnames
                if d not in excluded and not d.startswith(".")
            ]
            for filename in filenames:
                if not filename.endswith(".py"):
                    continue
                # Check filename against exclusion patterns (supports fnmatch globs)
                if any(fnmatch.fnmatch(filename, pat) for pat in excluded):
                    continue
                full = pathlib.Path(dirpath) / filename
                try:
                    if full.stat().st_size > max_kb * 1024:
                        continue
                except OSError:
                    continue
                yield full

    @staticmethod
    def _scan_one(filepath: str, report: ScanReport) -> None:
        """Read and scan one file, appending to report."""
        try:
            source = pathlib.Path(filepath).read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            report.errors.append({"file": filepath, "error": str(exc)})
            return

        Scanner._scan_source_text(source, filepath, report)

    @staticmethod
    def _scan_source_text(source: str, filename: str, report: ScanReport) -> None:
        """Parse and scan a source text string."""
        try:
            tree = ast.parse(source, filename=filename)
        except SyntaxError as exc:
            report.errors.append({
                "file":  filename,
                "error": f"SyntaxError at line {exc.lineno}: {exc.msg}",
            })
            return

        source_lines = source.splitlines()
        visitor = _ClassicalCryptoVisitor(filename, source_lines)
        visitor.visit(tree)
        report.findings.extend(visitor.findings)
        report.files_scanned += 1
