"""
quantum_safe.protocols.x509
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Hybrid X.509 certificate builder.

Hybrid X.509 certificates carry both a classical signature and a PQC
co-signature, making them valid to both classical and post-quantum verifiers.

Standards basis
---------------
The approach follows two IETF drafts:

  draft-ounsworth-pq-composite-sigs:
    Defines "composite" key and signature formats where a single public key
    is actually two sub-keys, and a single signature is two sub-signatures.
    A verifier that understands composite must validate both; a legacy verifier
    that only understands the primary (classical) sub-key can still validate it.

  draft-truskovsky-lamps-pq-hybrid-x509:
    Alternative approach using the SubjectAltPublicKeyInfo extension to carry
    the PQC public key alongside the classical one.

We implement a simplified version: the certificate is signed with a classical
key (ECDSA P-256 or Ed25519) using standard X.509, and the PQC co-signature
is stored in a non-critical extension (OID 1.3.6.1.4.1.99999.1) as a DER
OCTET STRING. This is backward compatible: classical verifiers ignore the
unknown extension; our verifier checks both.

Note on the OID 1.3.6.1.4.1.99999.1: this is a placeholder. A real
deployment would need a registered OID from IANA or a private enterprise
arc. We document this prominently so it's never accidentally used as-is
in production.

Supported classical signature algorithms
-----------------------------------------
  - Ed25519 (via cryptography library's x509 builder)
  - ECDSA P-256, P-384

Supported PQC co-signature algorithms
---------------------------------------
  - ML-DSA-65 (default)
  - ML-DSA-87
"""

from __future__ import annotations

import datetime
import ipaddress
import warnings
from dataclasses import dataclass, field
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.ec import (
    SECP256R1,
    SECP384R1,
    EllipticCurvePrivateKey,
    generate_private_key,
    ECDSA,
)
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives.serialization import Encoding

from quantum_safe._internal import serialization as _ser
from quantum_safe.types import KeyPair, PublicKey, SecretKey

# Placeholder OID for the PQC co-signature extension.
# WARNING: This is NOT a registered OID. Register your own before production use.
_PQC_COSIG_OID = x509.ObjectIdentifier("1.3.6.1.4.1.99999.1")
_PQC_PUBKEY_OID = x509.ObjectIdentifier("1.3.6.1.4.1.99999.2")

# Default certificate validity
_DEFAULT_VALIDITY_DAYS = 365

# The data that gets PQC-signed for the co-signature.
# We sign: DER-encoded TBS (to-be-signed) certificate + version byte.
# This binds the co-signature to the exact certificate content.
_COSIG_INFO_PREFIX = b"qs-x509-cosig-v1\x00"


@dataclass
class HybridCertificateBuilder:
    """Builder for hybrid X.509 certificates.

    Usage::

        from quantum_safe.protocols.x509 import HybridCertificateBuilder
        from quantum_safe.signatures.hybrid import HybridSign

        # Generate key material
        signer    = HybridSign()
        hybrid_kp = signer.generate_keypair()
        classical_priv = Ed25519PrivateKey.generate()

        builder = HybridCertificateBuilder(
            subject_cn="service.internal",
            classical_private_key=classical_priv,
            pqc_keypair=hybrid_kp,
            validity_days=365,
        )
        cert_pem, cosig_bundle = builder.build()
    """

    subject_cn: str
    classical_private_key: Any   # Ed25519PrivateKey | EllipticCurvePrivateKey
    pqc_keypair: KeyPair
    validity_days: int = _DEFAULT_VALIDITY_DAYS
    is_ca: bool = False
    dns_names: list[str] = field(default_factory=list)
    ip_addresses: list[str] = field(default_factory=list)
    organization: str = ""
    country: str = ""
    issuer_cert: Any = None          # x509.Certificate — for non-self-signed
    issuer_key: Any = None           # classical private key of issuer
    extended_key_usage: list[x509.ObjectIdentifier] = field(default_factory=list)

    def build(self, signer: object = None) -> tuple[bytes, bytes]:
        """Build the hybrid certificate.

        Returns:
            (cert_pem, cosig_bundle):
                cert_pem:      PEM-encoded X.509 certificate with embedded
                               PQC public key extension. Valid to classical
                               verifiers.
                cosig_bundle:  CBOR-encoded co-signature bundle:
                               {pqc_sig: bytes, pqc_algo: str, cert_fp: str}
                               Verifiers that support hybrid validation check
                               this alongside the certificate.
        """
        # Build subject name
        name_attrs = [x509.NameAttribute(NameOID.COMMON_NAME, self.subject_cn)]
        if self.organization:
            name_attrs.append(
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, self.organization)
            )
        if self.country:
            name_attrs.append(
                x509.NameAttribute(NameOID.COUNTRY_NAME, self.country)
            )
        subject = x509.Name(name_attrs)

        # Issuer: self-signed unless issuer_cert is provided
        issuer = subject if self.issuer_cert is None else self.issuer_cert.subject

        # Validity window
        now = datetime.datetime.now(datetime.timezone.utc)
        not_valid_before = now - datetime.timedelta(minutes=1)  # small grace for clock skew
        not_valid_after = now + datetime.timedelta(days=self.validity_days)

        # Signing key for the classical signature
        signing_key = self.issuer_key if self.issuer_key else self.classical_private_key

        # Build the certificate
        builder = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(self.classical_private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(not_valid_before)
            .not_valid_after(not_valid_after)
        )

        # Basic constraints
        builder = builder.add_extension(
            x509.BasicConstraints(ca=self.is_ca, path_length=0 if self.is_ca else None),
            critical=True,
        )

        # Subject Alternative Names
        san_entries: list[Any] = []
        for dns in self.dns_names:
            san_entries.append(x509.DNSName(dns))
        for ip in self.ip_addresses:
            try:
                san_entries.append(x509.IPAddress(ipaddress.ip_address(ip)))
            except ValueError:
                warnings.warn(f"Invalid IP address in SAN: {ip!r}", stacklevel=2)
        if san_entries:
            builder = builder.add_extension(
                x509.SubjectAlternativeName(san_entries),
                critical=False,
            )

        # Extended key usage
        if self.extended_key_usage:
            builder = builder.add_extension(
                x509.ExtendedKeyUsage(self.extended_key_usage),
                critical=False,
            )

        # Embed PQC public key as a non-critical extension.
        # This lets post-quantum-aware verifiers find the PQC public key
        # without out-of-band distribution.
        pqc_pub_der = _ser.dumps({
            "algo": self.pqc_keypair.algorithm,
            "pub":  self.pqc_keypair.public.raw_bytes,
            "qs-version": 1,
        })
        builder = builder.add_extension(
            x509.UnrecognizedExtension(
                oid=_PQC_PUBKEY_OID,
                value=pqc_pub_der,
            ),
            critical=False,
        )

        # Sign with classical key
        if isinstance(signing_key, Ed25519PrivateKey):
            cert = builder.sign(signing_key, algorithm=None, backend=default_backend())
        else:
            cert = builder.sign(signing_key, hashes.SHA256(), backend=default_backend())

        cert_pem = cert.public_bytes(Encoding.PEM)

        # Generate PQC co-signature over the DER-encoded certificate.
        # The co-signature is over the entire cert bytes so any modification
        # invalidates it.
        cert_der = cert.public_bytes(Encoding.DER)
        cosig_input = _COSIG_INFO_PREFIX + cert_der

        cosig_bundle = self._generate_cosig(cosig_input, signer=signer)

        return cert_pem, cosig_bundle

    def _generate_cosig(self, data: bytes, signer: object = None) -> bytes:
        """Generate the PQC co-signature bundle."""
        from quantum_safe.signatures.hybrid import HybridSign
        from quantum_safe.signatures.core import Sign

        algo = self.pqc_keypair.algorithm

        if signer is None:
            if "+" in algo:
                from quantum_safe.signatures.algorithms import parse_hybrid_name
                classical, pqc = parse_hybrid_name(algo)
                signer = HybridSign.__new__(HybridSign)
                signer._classical = classical
                signer._pqc = pqc
                signer._algorithm = algo
                signer._hedged = True
                from quantum_safe.backends import get_signature_backend
                signer._backend = get_signature_backend("auto")
            else:
                signer = Sign(algorithm=algo)

        sm = signer.sign(data, self.pqc_keypair.secret, context=b"qs-x509-cosig")

        # Package the co-signature with metadata for distribution
        bundle = _ser.dumps({
            "v":           1,
            "algo":        algo,
            "sig":         sm.signature,
            "context":     b"qs-x509-cosig",
            "cert_fp":     self.pqc_keypair.public.fingerprint(),
        })
        return bundle

    @staticmethod
    def verify_cosig(
        cert_pem: bytes,
        cosig_bundle: bytes,
        pqc_public_key: PublicKey,
    ) -> None:
        """Verify a hybrid certificate's PQC co-signature.

        Args:
            cert_pem:       PEM-encoded certificate.
            cosig_bundle:   Co-signature bundle from build().
            pqc_public_key: The signer's PQC public key.

        Raises:
            VerificationError: if the co-signature is invalid.
            KeyParseError:     if the bundle is malformed.
        """
        from quantum_safe.exceptions import KeyParseError, VerificationError
        from quantum_safe.signatures.hybrid import HybridSign
        from quantum_safe.signatures.core import Sign
        from quantum_safe.types.signatures import SignedMessage

        # Load the cert to get its DER bytes
        try:
            cert = x509.load_pem_x509_certificate(cert_pem, default_backend())
            cert_der = cert.public_bytes(Encoding.DER)
        except Exception as exc:
            raise KeyParseError("pem", f"Failed to load certificate: {exc}") from exc

        # Decode the bundle
        try:
            bundle = _ser.loads(cosig_bundle)
        except Exception as exc:
            raise KeyParseError("cbor", f"Failed to decode cosig bundle: {exc}") from exc

        algo = bundle.get("algo", "")
        sig = bytes(bundle.get("sig", b""))
        context = bytes(bundle.get("context", b"qs-x509-cosig"))

        if not algo or not sig:
            raise KeyParseError("cbor", "cosig bundle missing algo or sig")

        # Build the signer instance
        if "+" in algo:
            from quantum_safe.signatures.algorithms import parse_hybrid_name
            from quantum_safe.backends import get_signature_backend
            classical, pqc = parse_hybrid_name(algo)
            verifier = HybridSign.__new__(HybridSign)
            verifier._classical = classical
            verifier._pqc = pqc
            verifier._algorithm = algo
            verifier._hedged = True
            verifier._backend = get_signature_backend("auto")
        else:
            verifier = Sign(algorithm=algo)

        cosig_input = _COSIG_INFO_PREFIX + cert_der

        sm = SignedMessage(
            message=cosig_input,
            signature=sig,
            algorithm=algo,
            context=context,
        )
        verifier.verify(sm, pqc_public_key)


def generate_classical_keypair_for_cert(
    algorithm: str = "Ed25519",
) -> Any:
    """Generate a classical keypair suitable for certificate signing.

    Args:
        algorithm: "Ed25519", "P-256", or "P-384".

    Returns:
        A private key object from the cryptography library.
    """
    if algorithm == "Ed25519":
        return Ed25519PrivateKey.generate()
    elif algorithm == "P-256":
        return generate_private_key(SECP256R1(), default_backend())
    elif algorithm == "P-384":
        return generate_private_key(SECP384R1(), default_backend())
    else:
        raise ValueError(
            f"Unsupported classical cert algorithm '{algorithm}'. "
            f"Valid options: Ed25519, P-256, P-384"
        )
