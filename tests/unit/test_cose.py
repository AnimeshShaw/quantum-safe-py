"""
COSE_Sign1 with ML-DSA (RFC 9964, the COSE half), and AKP COSE keys.

Independent known answers: ``tests/interop/vectors/rfc9964_cose_vectors.json`` is RFC 9964 Appendix A
(ML-DSA-44/65/87: an all-zero-seed key, a COSE_Sign1 with the key id in the protected header, and the
exact bytes that are signed). Signing is hedged, so the RFC's signature bytes cannot be reproduced; the
RFC's signed bytes (the Sig_structure) must be, and the RFC's signatures must verify.
"""

from __future__ import annotations

import json
import pathlib

import cbor2
import pytest

from quantum_safe.exceptions import VerificationError

pytestmark = pytest.mark.requires_liboqs

RFC = json.loads(
    (
        pathlib.Path(__file__).resolve().parents[1]
        / "interop"
        / "vectors"
        / "rfc9964_cose_vectors.json"
    ).read_text(encoding="utf-8")
)["vectors"]
PAYLOAD = b"hello post quantum signatures"


def _pub(v):
    from quantum_safe.types import PublicKey

    return PublicKey(bytes.fromhex(v["public_key"]), v["algorithm"])


@pytest.mark.parametrize("v", RFC, ids=[v["algorithm"] for v in RFC])
class TestRfc9964Vectors:
    def test_verifies_the_rfc_signature(self, v) -> None:
        from quantum_safe.protocols.cose import verify_sign1

        assert verify_sign1(bytes.fromhex(v["sign1"]), _pub(v)) == PAYLOAD

    def test_to_be_signed_matches_the_rfc(self, v) -> None:
        from quantum_safe.protocols.cose import sig_structure

        parsed = cbor2.loads(bytes.fromhex(v["sign1"])).value
        protected = parsed[0]
        assert sig_structure(protected, PAYLOAD) == bytes.fromhex(v["to_be_signed"])

    def test_inspect_reports_alg_kid_and_tag(self, v) -> None:
        from quantum_safe.protocols.cose import inspect_sign1

        info = inspect_sign1(bytes.fromhex(v["sign1"]))
        assert info["algorithm"] == v["algorithm"] and info["cose_alg"] == v["cose_alg"]
        assert info["kid"] == bytes.fromhex(v["kid"]) and info["tagged"] is True

    def test_our_signature_over_the_same_header_signs_the_same_bytes(self, v) -> None:
        """Same payload, same key id, same algorithm: the signed bytes equal the RFC's exactly."""
        from quantum_safe.protocols.cose import sig_structure, sign1, verify_sign1
        from quantum_safe.signatures.core import Sign

        kp = Sign(v["algorithm"]).generate_keypair()
        blob = sign1(PAYLOAD, kp.secret, kid=bytes.fromhex(v["kid"]))
        protected = cbor2.loads(blob).value[0]
        assert sig_structure(protected, PAYLOAD) == bytes.fromhex(v["to_be_signed"])
        assert verify_sign1(blob, kp.public) == PAYLOAD

    def test_rfc_signature_fails_for_changed_inputs(self, v) -> None:
        from quantum_safe.protocols.cose import verify_sign1

        data = bytes.fromhex(v["sign1"])
        with pytest.raises(VerificationError):
            verify_sign1(data, _pub(v), external_aad=b"x")
        arr = cbor2.loads(data).value
        bad_payload = cbor2.dumps(cbor2.CBORTag(18, [arr[0], arr[1], PAYLOAD + b"!", arr[3]]))
        with pytest.raises(VerificationError):
            verify_sign1(bad_payload, _pub(v))
        sig = bytearray(arr[3])
        sig[0] ^= 1
        bad_sig = cbor2.dumps(cbor2.CBORTag(18, [arr[0], arr[1], arr[2], bytes(sig)]))
        with pytest.raises(VerificationError):
            verify_sign1(bad_sig, _pub(v))


@pytest.fixture(scope="module")
def kp65():
    from quantum_safe.signatures.core import Sign

    return Sign("ML-DSA-65").generate_keypair()


class TestSignVerify:
    @pytest.mark.parametrize("level", ["ML-DSA-44", "ML-DSA-65", "ML-DSA-87"])
    def test_round_trip(self, level: str) -> None:
        from quantum_safe.protocols.cose import inspect_sign1, sign1, verify_sign1
        from quantum_safe.signatures.core import Sign

        kp = Sign(level).generate_keypair()
        blob = sign1(b"payload", kp.secret, kid=b"key-1")
        assert verify_sign1(blob, kp.public) == b"payload"
        assert inspect_sign1(blob)["algorithm"] == level

    def test_untagged_and_tagged(self, kp65) -> None:
        from quantum_safe.protocols.cose import inspect_sign1, sign1, verify_sign1

        tagged, untagged = sign1(b"m", kp65.secret), sign1(b"m", kp65.secret, tagged=False)
        assert (
            inspect_sign1(tagged)["tagged"] is True and inspect_sign1(untagged)["tagged"] is False
        )
        assert verify_sign1(tagged, kp65.public) == verify_sign1(untagged, kp65.public) == b"m"

    def test_external_aad_is_bound(self, kp65) -> None:
        from quantum_safe.protocols.cose import sign1, verify_sign1

        blob = sign1(b"m", kp65.secret, external_aad=b"ctx")
        assert verify_sign1(blob, kp65.public, external_aad=b"ctx") == b"m"
        with pytest.raises(VerificationError):
            verify_sign1(blob, kp65.public)

    def test_detached_payload(self, kp65) -> None:
        from quantum_safe.protocols.cose import sign1, verify_sign1

        blob = sign1(b"big document", kp65.secret, detached=True)
        assert cbor2.loads(blob).value[2] is None
        assert verify_sign1(blob, kp65.public, detached_payload=b"big document") == b"big document"
        with pytest.raises(VerificationError):
            verify_sign1(blob, kp65.public, detached_payload=b"other")
        with pytest.raises(ValueError):
            verify_sign1(blob, kp65.public)  # detached but no payload supplied

    def test_wrong_key(self, kp65) -> None:
        from quantum_safe.protocols.cose import sign1, verify_sign1
        from quantum_safe.signatures.core import Sign

        other = Sign("ML-DSA-65").generate_keypair()
        with pytest.raises(VerificationError):
            verify_sign1(sign1(b"m", kp65.secret), other.public)

    def test_key_of_another_level_is_refused(self, kp65) -> None:
        from quantum_safe.protocols.cose import sign1, verify_sign1
        from quantum_safe.signatures.core import Sign

        other = Sign("ML-DSA-44").generate_keypair()
        with pytest.raises(ValueError, match="algorithm"):
            verify_sign1(sign1(b"m", kp65.secret), other.public)

    def test_only_plain_ml_dsa(self) -> None:
        from quantum_safe.protocols.cose import sign1
        from quantum_safe.signatures.core import Sign

        slh = Sign("SLH-DSA-SHAKE-128f").generate_keypair()
        with pytest.raises(ValueError, match="ML-DSA"):
            sign1(b"m", slh.secret)


class TestStrictParsing:
    def _parts(self, kp65):
        from quantum_safe.protocols.cose import sign1

        return cbor2.loads(sign1(b"m", kp65.secret, kid=b"k")).value

    def test_malformed_inputs(self, kp65) -> None:
        from quantum_safe.protocols.cose import verify_sign1

        good = cbor2.dumps(cbor2.CBORTag(18, self._parts(kp65)))
        for bad in (
            b"",
            b"\xff",
            good + b"\x00",  # trailing bytes
            cbor2.dumps([1, 2, 3]),
            cbor2.dumps(cbor2.CBORTag(18, [b"", {}, b"m"])),  # three elements
            cbor2.dumps(cbor2.CBORTag(98, self._parts(kp65))),  # COSE_Sign, not Sign1
        ):
            with pytest.raises(ValueError):
                verify_sign1(bad, kp65.public)

    def test_algorithm_must_be_protected_and_known(self, kp65) -> None:
        from quantum_safe.protocols.cose import verify_sign1

        parts = self._parts(kp65)
        no_alg = cbor2.dumps(cbor2.CBORTag(18, [cbor2.dumps({4: b"k"}), {}, parts[2], parts[3]]))
        with pytest.raises(ValueError):
            verify_sign1(no_alg, kp65.public)
        unprotected_alg = cbor2.dumps(cbor2.CBORTag(18, [b"\xa0", {1: -49}, parts[2], parts[3]]))
        with pytest.raises(ValueError):
            verify_sign1(unprotected_alg, kp65.public)
        unknown = cbor2.dumps(cbor2.CBORTag(18, [cbor2.dumps({1: -7}), {}, parts[2], parts[3]]))
        with pytest.raises(ValueError):
            verify_sign1(unknown, kp65.public)  # ES256 is not an ML-DSA algorithm

    def test_crit_header_is_refused(self, kp65) -> None:
        from quantum_safe.protocols.cose import verify_sign1

        parts = self._parts(kp65)
        crit = cbor2.dumps(
            cbor2.CBORTag(18, [cbor2.dumps({1: -49, 2: [99]}), {}, parts[2], parts[3]])
        )
        with pytest.raises(ValueError):
            verify_sign1(crit, kp65.public)

    def test_protected_header_with_duplicate_labels_is_refused(self, kp65) -> None:
        from quantum_safe.protocols.cose import verify_sign1

        parts = self._parts(kp65)
        dup = bytes.fromhex("a301382f0138300440")  # {1: -48, 1: -49, 4: h''}: duplicate label 1
        data = cbor2.dumps(cbor2.CBORTag(18, [dup, {}, parts[2], parts[3]]))
        with pytest.raises(ValueError):
            verify_sign1(data, kp65.public)


class TestCoseKey:
    @pytest.mark.parametrize("v", RFC, ids=[v["algorithm"] for v in RFC])
    def test_public_key_matches_the_rfc_shape(self, v) -> None:
        from quantum_safe.protocols.cose import decode_cose_key, encode_cose_key

        encoded = encode_cose_key(_pub(v), kid=bytes.fromhex(v["kid"]))
        m = cbor2.loads(encoded)
        assert m[1] == 7 and m[3] == v["cose_alg"] and m[-1] == bytes.fromhex(v["public_key"])
        assert m[2] == bytes.fromhex(v["kid"]) and -2 not in m
        pub, kid = decode_cose_key(encoded)
        assert pub.algorithm == v["algorithm"] and pub.raw_bytes == bytes.fromhex(v["public_key"])
        assert kid == bytes.fromhex(v["kid"])

    def test_decode_refuses_private_and_malformed_keys(self) -> None:
        from quantum_safe.protocols.cose import decode_cose_key

        pub = bytes.fromhex(RFC[0]["public_key"])
        good = {1: 7, 3: -48, -1: pub}
        assert decode_cose_key(cbor2.dumps(good))[0].algorithm == "ML-DSA-44"
        for bad in (
            good | {1: 2},  # not AKP
            good | {3: -7},  # not ML-DSA
            {k: v for k, v in good.items() if k != 3},  # no alg (REQUIRED)
            good | {-1: pub[:-1]},  # wrong public key length
            good | {-2: b"\x00" * 32},  # private key material: use the private-key API
        ):
            with pytest.raises(ValueError):
                decode_cose_key(cbor2.dumps(bad))


TS_VECTORS = json.loads(
    (
        pathlib.Path(__file__).resolve().parents[1] / "interop" / "vectors" / "ts_cose_vectors.json"
    ).read_text(encoding="utf-8")
)["vectors"]


class TestInteropWithTypeScript:
    @pytest.mark.parametrize("i", range(len(TS_VECTORS)))
    def test_verifies_what_typescript_signed(self, i: int) -> None:
        from quantum_safe.protocols.cose import verify_sign1
        from quantum_safe.types import PublicKey

        v = TS_VECTORS[i]
        pub = PublicKey(bytes.fromhex(v["public_key"]), v["algorithm"])
        payload = bytes.fromhex(v["payload"])
        aad = bytes.fromhex(v["external_aad"])
        message = bytes.fromhex(v["message"])
        if v["detached"]:
            got = verify_sign1(message, pub, external_aad=aad, detached_payload=payload)
        else:
            got = verify_sign1(message, pub, external_aad=aad)
        assert got == payload

    def test_vectors_cover_levels_and_options(self) -> None:
        assert {v["algorithm"] for v in TS_VECTORS} == {"ML-DSA-44", "ML-DSA-65", "ML-DSA-87"}
        assert {v["case"] for v in TS_VECTORS} >= {
            "tagged with kid",
            "untagged",
            "external aad",
            "detached",
        }
