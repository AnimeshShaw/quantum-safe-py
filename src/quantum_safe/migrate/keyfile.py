"""
quantum_safe.migrate.keyfile
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The file handling behind ``qs-migrate upgrade-key``: read a classical secret key,
upgrade it with :class:`~quantum_safe.migrate.upgrader.Upgrader`, check the result
and write it without ever leaving a partial or world-readable key file behind.

Supported inputs are an X25519, Ed25519, P-256 or P-384 **secret** key, either as a
standard PKCS#8 ``PRIVATE KEY`` PEM or as this library's own ``QUANTUM SAFE SECRET KEY``
PEM. An elliptic-curve key (P-256, P-384) can serve key agreement or signatures, so the
caller says which one it is (``--key-type kem`` or ``sign``). A public key alone cannot
be upgraded: the hybrid key must contain the existing secret, and the new post-quantum
secret has to be stored with it. Everything else (RSA, encrypted keys, keys that are
already hybrid or post-quantum) is rejected with a message that says why, before
anything is written.
"""

from __future__ import annotations

import os
import secrets
from dataclasses import dataclass
from pathlib import Path

from quantum_safe.types import KeyPair, MigrationState, PublicKey, SecretKey

#: Algorithm -> (key type, default hybrid target) for the inputs the CLI upgrades.
SUPPORTED_INPUTS: dict[str, tuple[str, str]] = {
    "X25519": ("kem", "X25519+ML-KEM-768"),
    "Ed25519": ("sign", "Ed25519+ML-DSA-65-v2"),
}

#: Elliptic-curve inputs: the key can be used either way, so the key type is chosen by the caller.
#: Curve -> {key type -> default hybrid target}.
EC_INPUTS: dict[str, dict[str, str]] = {
    "P-256": {"kem": "P-256+ML-KEM-768", "sign": "P-256+ML-DSA-65-v2"},
    "P-384": {"kem": "P-384+ML-KEM-1024", "sign": "P-384+ML-DSA-87-v2"},
}

_MAX_KEY_FILE_BYTES = 64 * 1024
_SECRET_LABEL = "QUANTUM SAFE SECRET KEY"  # noqa: S105 (a PEM label, not a password)
_PUBLIC_LABEL = "QUANTUM SAFE PUBLIC KEY"


class KeyUpgradeError(Exception):
    """A key could not be upgraded. The message is safe to show to the user."""


@dataclass(frozen=True)
class UpgradedFiles:
    """What ``upgrade_key_file`` wrote.

    Attributes:
        secret_path: where the hybrid secret key was written.
        public_path: where the hybrid public key was written.
        old_algorithm: the classical algorithm of the input key (for example ``"X25519"``).
        new_algorithm: the hybrid algorithm of the written keys.
        key_type: ``"kem"`` or ``"sign"``.
        notes: the human-readable note from the :class:`~quantum_safe.migrate.upgrader.Upgrader`
            result.
    """

    secret_path: Path
    public_path: Path
    old_algorithm: str
    new_algorithm: str
    key_type: str
    notes: str


def _classical_from_raw(algorithm: str, raw: bytes) -> tuple[bytes, bytes]:
    """Return (secret, public) raw bytes for an X25519 / Ed25519 secret key."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    from cryptography.hazmat.primitives.serialization import (
        Encoding,
        PublicFormat,
        load_pem_private_key,
    )

    if algorithm in EC_INPUTS:
        # The classical secret is kept as PKCS#8 PEM text (as the hybrid keys store it); the
        # public key is the uncompressed SEC1 point. A signing key uses it without the 0x04 tag.
        key = load_pem_private_key(raw, password=None)
        point = key.public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
        return raw, point
    if len(raw) != 32:
        raise KeyUpgradeError(f"a {algorithm} secret key is 32 bytes, this one is {len(raw)}")
    priv = X25519PrivateKey if algorithm == "X25519" else Ed25519PrivateKey
    public = priv.from_private_bytes(raw).public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return raw, public


def load_classical_secret(path: str | Path) -> tuple[str, bytes, bytes]:
    """Read ``path`` and return ``(algorithm, secret_raw, public_raw)``.

    Raises :class:`KeyUpgradeError` for anything that cannot be upgraded, saying why.

    The file must be at most 64 KiB of UTF-8 text. ``algorithm`` is ``"X25519"``,
    ``"Ed25519"``, ``"P-256"`` or ``"P-384"``. For X25519 and Ed25519 ``secret_raw`` and
    ``public_raw`` are the 32-byte raw keys. For the elliptic-curve keys ``secret_raw`` is the
    PKCS#8 PEM text as bytes and ``public_raw`` is the uncompressed SEC1 point.
    """
    p = Path(path)
    try:
        if p.stat().st_size > _MAX_KEY_FILE_BYTES:
            raise KeyUpgradeError(f"{p} is too large to be a key file")
        text = p.read_bytes().decode("utf-8")
    except OSError as exc:
        raise KeyUpgradeError(f"cannot read {p}: {exc.strerror or exc}") from exc
    except UnicodeDecodeError:
        raise KeyUpgradeError(f"{p} is not a PEM text file") from None

    first = text.strip().splitlines()[0] if text.strip() else ""

    if _PUBLIC_LABEL in first or "BEGIN PUBLIC KEY" in first:
        raise KeyUpgradeError(
            "this is a public key. Upgrading needs the secret key: the hybrid key must hold "
            "the existing secret next to the new post-quantum one. Provide the secret key file."
        )

    if _SECRET_LABEL in first:
        try:
            key = SecretKey.from_pem(text)
        except Exception as exc:
            raise KeyUpgradeError(f"could not parse the key: {exc}") from exc
        algorithm, raw = key.algorithm, key.raw_bytes
    elif "BEGIN PRIVATE KEY" in first:
        algorithm, raw = _from_pkcs8(text)
    elif "ENCRYPTED PRIVATE KEY" in first:
        raise KeyUpgradeError(
            "the key is encrypted; decrypt it first (this command does not take a passphrase)"
        )
    else:
        raise KeyUpgradeError(
            "not a recognised key file. Expected a PKCS#8 'PRIVATE KEY' PEM or a "
            f"'{_SECRET_LABEL}' PEM"
        )

    if algorithm not in SUPPORTED_INPUTS and algorithm not in EC_INPUTS:
        if "+" in algorithm or algorithm.startswith(("ML-", "SLH-", "BIKE", "HQC")):
            raise KeyUpgradeError(
                f"the key is already post-quantum ({algorithm}); there is nothing to upgrade"
            )
        raise KeyUpgradeError(
            f"{algorithm} keys are not upgraded by this command (supported: "
            f"{', '.join([*SUPPORTED_INPUTS, *EC_INPUTS])}). Use Upgrader from Python for other "
            f"algorithms."
        )
    secret, public = _classical_from_raw(algorithm, raw)
    return algorithm, secret, public


def _from_pkcs8(text: str) -> tuple[str, bytes]:
    """Parse an unencrypted PKCS#8 PEM and return ``(algorithm, secret)``.

    X25519 and Ed25519 give the 32 raw bytes; P-256 and P-384 give the key re-encoded as PKCS#8
    PEM bytes. Any other key type or curve raises :class:`KeyUpgradeError`.
    """
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    from cryptography.hazmat.primitives.serialization import (
        Encoding,
        NoEncryption,
        PrivateFormat,
        load_pem_private_key,
    )

    try:
        key = load_pem_private_key(text.encode("ascii"), password=None)
    except Exception as exc:
        raise KeyUpgradeError(f"could not parse the PKCS#8 key: {exc}") from exc
    from cryptography.hazmat.primitives.asymmetric.ec import (
        SECP256R1,
        SECP384R1,
        EllipticCurvePrivateKey,
    )

    if isinstance(key, EllipticCurvePrivateKey):
        if isinstance(key.curve, SECP384R1):
            curve = "P-384"
        elif isinstance(key.curve, SECP256R1):
            curve = "P-256"
        else:
            raise KeyUpgradeError(
                f"EC keys on the curve {key.curve.name} are not upgraded by this command "
                f"(supported curves: {', '.join(EC_INPUTS)})"
            )
        return curve, key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
    if isinstance(key, X25519PrivateKey):
        algorithm = "X25519"
    elif isinstance(key, Ed25519PrivateKey):
        algorithm = "Ed25519"
    else:
        raise KeyUpgradeError(
            f"{type(key).__name__.removesuffix('PrivateKey')} keys are not upgraded by this "
            f"command (supported: {', '.join([*SUPPORTED_INPUTS, *EC_INPUTS])})"
        )
    return algorithm, key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())


def resolve_target(
    algorithm: str, key_type: str | None, target: str | None
) -> tuple[str, str, str]:
    """Check ``--key-type`` and ``--target`` against the input.

    Returns ``(key_type, classical, pqc)``.

    Args:
        algorithm: the classical algorithm of the input key, as returned by
            :func:`load_classical_secret`.
        key_type: ``"kem"`` or ``"sign"``, or ``None`` to use the input's own type. Required for
            the elliptic-curve inputs (P-256, P-384), which can serve either purpose.
        target: the hybrid algorithm to produce, for example ``"X25519+ML-KEM-768"``, or ``None``
            for the default of the input and key type. A signing target may end in ``-v2``.

    Returns:
        ``(key_type, classical, pqc)``: the key type, the classical component (equal to
        ``algorithm``) and the post-quantum component of the target (``-v2`` suffix kept).

    Raises:
        KeyUpgradeError: ``key_type`` is missing for an elliptic-curve key or does not match the
            input; ``target`` is malformed, keeps a different classical component, or is not an
            approved combination.
    """
    if algorithm in EC_INPUTS:
        if key_type not in ("kem", "sign"):
            raise KeyUpgradeError(
                f"a {algorithm} key can be used for key agreement or for signatures: "
                f"pass --key-type kem or --key-type sign"
            )
        expected_type, default_target = key_type, EC_INPUTS[algorithm][key_type]
    else:
        expected_type, default_target = SUPPORTED_INPUTS[algorithm]
    if key_type is not None and key_type != expected_type:
        raise KeyUpgradeError(
            f"--key-type {key_type} does not match the input: an {algorithm} key is a "
            f"'{expected_type}' key"
        )
    target = target or default_target
    classical, sep, pqc = target.partition("+")
    if not sep or not pqc or "+" in pqc:
        raise KeyUpgradeError(f"--target must look like '{default_target}', got '{target}'")
    if classical != algorithm:
        raise KeyUpgradeError(
            f"--target {target} keeps a {classical} component, but the input is an {algorithm} key"
        )
    # Reuse the library's own approved-combination check for the right family.
    try:
        if expected_type == "kem":
            from quantum_safe.kem.algorithms import validate_hybrid_combination
        else:
            from quantum_safe.signatures.algorithms import validate_hybrid_combination
        base = pqc.removesuffix("-v2") if expected_type == "sign" else pqc
        validate_hybrid_combination(classical, base)
        if expected_type == "sign" and base != pqc:
            from quantum_safe.signatures import _v2

            if base not in _v2.V2_HYBRIDS.get(classical, ()):
                raise ValueError(f"{classical}+{pqc} is not a -v2 combination")
    except ValueError as exc:
        raise KeyUpgradeError(str(exc)) from exc
    return expected_type, classical, pqc


def _check_result(
    keypair: KeyPair, new_algorithm: str, key_type: str, classical: str, pqc: str
) -> None:
    """Round-trip the written PEMs and exercise the new key before anything is written."""
    pub = PublicKey.from_pem(keypair.public.to_pem())
    sec = SecretKey.from_pem(keypair.secret.to_pem())
    if pub.algorithm != new_algorithm or sec.algorithm != new_algorithm:
        raise KeyUpgradeError(
            f"internal check failed: expected {new_algorithm}, got {pub.algorithm}/{sec.algorithm}"
        )
    if MigrationState.HYBRID_TRANSITION not in (pub.migration_state, sec.migration_state):
        raise KeyUpgradeError("internal check failed: the upgraded key lost its migration state")
    if key_type == "kem":
        from quantum_safe.kem.hybrid import HybridKEM

        kem = HybridKEM(classical=classical, pqc=pqc)
        ciphertext, secret_a = kem.encapsulate(pub)
        if kem.decapsulate(sec, ciphertext) != secret_a:
            raise KeyUpgradeError("internal check failed: the upgraded KEM key did not round-trip")
    else:
        from quantum_safe.signatures.hybrid import HybridSign

        signer = HybridSign(classical=classical, pqc=pqc)
        signer.verify(signer.sign(b"qs-migrate upgrade-key self-check", sec), pub, context=b"")


def _write_temp(directory: Path, name: str, text: str) -> Path:
    """Write ASCII ``text`` to a new hidden ``.<name>.<random>.tmp`` file in ``directory``.

    The file is created exclusively with mode 0600, flushed and fsynced; its path is returned. It
    is removed again if writing fails. The caller renames it into place.
    """
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
    tmp = directory / f".{name}.{secrets.token_hex(6)}.tmp"
    # Private to the owner. The public key is not secret, but it need not be world-readable
    # by default either; whoever publishes it can relax the mode.
    fd = os.open(tmp, flags, 0o600)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(text.encode("ascii"))
            fh.flush()
            os.fsync(fh.fileno())
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise
    return tmp


def _copy_private(path: Path) -> Path:
    """Copy ``path`` to a new hidden ``.<name>.<random>.bak`` file in its directory.

    The copy is created exclusively with mode 0600, flushed and fsynced; its path is returned. It
    holds what ``path`` held, so a ``--force`` run can put the previous file back if it fails
    half way. The copy is removed again if writing fails.
    """
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
    backup = path.parent / f".{path.name}.{secrets.token_hex(6)}.bak"
    fd = os.open(backup, flags, 0o600)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(path.read_bytes())
            fh.flush()
            os.fsync(fh.fileno())
    except BaseException:
        backup.unlink(missing_ok=True)
        raise
    return backup


def upgrade_key_file(
    input_path: str | Path,
    output_path: str | Path,
    public_output_path: str | Path | None = None,
    *,
    target: str | None = None,
    key_type: str | None = None,
    force: bool = False,
    backend: str = "auto",
) -> UpgradedFiles:
    """Upgrade the classical secret key in ``input_path`` and write the hybrid key pair.

    Both files are created with mode 0600 on POSIX. The hybrid secret key goes to
    ``output_path`` and the hybrid public key to ``public_output_path`` (default:
    ``output_path`` + ``.pub``). The input
    file is never modified. Neither output is replaced unless ``force`` is set, both are
    written through temporary files and renamed into place, and on any failure the outputs are
    as they were before the call: a file this run created is removed, and with ``force`` a file
    it replaced is put back.

    Raises :class:`KeyUpgradeError` with a user-facing message on every failure.

    Args:
        input_path: the classical secret key file (see :func:`load_classical_secret`).
        output_path: where to write the hybrid secret key.
        public_output_path: where to write the hybrid public key; ``None`` or an empty value gives
            ``output_path`` + ``.pub``.
        target: the hybrid algorithm to produce; ``None`` selects the default for the input
            (see :func:`resolve_target`).
        key_type: ``"kem"`` or ``"sign"``. Optional for X25519 and Ed25519 (when given it must
            match), required for P-256 and P-384.
        force: replace ``output_path`` and ``public_output_path`` if they already exist.
        backend: the post-quantum backend name passed to the
            :class:`~quantum_safe.migrate.upgrader.Upgrader` (``"auto"`` by default).

    Returns:
        An :class:`UpgradedFiles` with the paths written, the old and new algorithm, the key
        type and the upgrade notes.

    Raises:
        KeyUpgradeError: the three paths are not distinct files, an output exists and ``force``
            is not set, an output directory is missing, the input cannot be read or upgraded, the
            upgraded key fails its round-trip self-check, or an output cannot be written.
    """
    from quantum_safe.migrate.upgrader import Upgrader

    src = Path(input_path)
    out = Path(output_path)
    pub_out = Path(public_output_path) if public_output_path else out.with_name(out.name + ".pub")

    paths = {src.resolve(), out.resolve(), pub_out.resolve()}
    if len(paths) != 3:
        raise KeyUpgradeError(
            "the input, --output and --public-output must be three different files"
        )
    for p in (out, pub_out):
        if p.exists() and not force:
            raise KeyUpgradeError(f"{p} already exists; choose another path or pass --force")
        if not p.parent.is_dir():
            raise KeyUpgradeError(f"the directory {p.parent} does not exist")

    algorithm, secret_raw, public_raw = load_classical_secret(src)
    kind, classical, pqc = resolve_target(algorithm, key_type, target)

    if kind == "sign" and algorithm in EC_INPUTS:
        public_raw = public_raw[1:]  # a signing key stores the raw x || y, without the 0x04 tag
    try:
        if kind == "kem":
            result = Upgrader.upgrade_kem_key(secret_raw, public_raw, classical, pqc, backend)
        else:
            result = Upgrader.upgrade_signing_key(secret_raw, public_raw, classical, pqc, backend)
        _check_result(result.new_keypair, result.new_algorithm, kind, classical, pqc)
    except KeyUpgradeError:
        raise
    except Exception as exc:
        raise KeyUpgradeError(f"the upgrade failed: {exc}") from exc

    secret_pem = result.new_keypair.secret.to_pem()
    public_pem = result.new_keypair.public.to_pem()

    existed = {out: out.exists(), pub_out: pub_out.exists()}
    temps: list[Path] = []
    placed: list[Path] = []
    backups: dict[Path, Path] = {}
    try:
        sec_tmp = _write_temp(out.parent, out.name, secret_pem)
        temps.append(sec_tmp)
        pub_tmp = _write_temp(pub_out.parent, pub_out.name, public_pem)
        temps.append(pub_tmp)
        for path in (out, pub_out):
            if existed[path]:  # only with --force: keep what is replaced until both are in place
                backups[path] = _copy_private(path)
        os.replace(sec_tmp, out)
        temps.remove(sec_tmp)
        placed.append(out)
        os.replace(pub_tmp, pub_out)
        temps.remove(pub_tmp)
    except OSError as exc:
        # Do not leave a new secret key beside the old public key (or the reverse): put back the
        # file a --force run replaced, and remove a file this run created.
        for path in placed:
            if path in backups:
                os.replace(backups.pop(path), path)
            elif not existed[path]:
                path.unlink(missing_ok=True)
        raise KeyUpgradeError(f"could not write the output: {exc.strerror or exc}") from exc
    finally:
        for tmp in [*temps, *backups.values()]:
            tmp.unlink(missing_ok=True)

    return UpgradedFiles(
        secret_path=out,
        public_path=pub_out,
        old_algorithm=algorithm,
        new_algorithm=result.new_algorithm,
        key_type=kind,
        notes=result.notes,
    )
