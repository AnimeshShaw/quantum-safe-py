"""Reverse-direction interop: data written by quantum-safe-ts must load here.

The vectors in ``vectors/`` were produced by quantum-safe-ts (the TypeScript /
WebAssembly library that is byte-compatible with this one), copied from its
``tests/vectors/`` at commit e99bec1:

- ``ts_vectors.json``: written by its Rust core (KEM ciphertexts, envelopes,
  keys in every format, signed messages in both hedging modes).
- ``ts_js_vectors.json``: written by its npm package (JWTs, envelopes,
  upgraded keys, a migration store).

Regenerate there with ``cargo run -p quantum-safe-core --example
gen_ts_vectors`` and ``node scripts/gen_ts_js_vectors.mjs``, then copy both
files here. This is the pytest port of that repository's
``scripts/verify_ts_vectors.py``.

Signatures made with hedged=False need a verifier built with hedged=False
(the prefix length is pinned to the verifier's mode), and every verifier is
given the context it expects.
"""

from __future__ import annotations

import json
import pathlib
import warnings

import pytest

from quantum_safe import KEM, HybridKEM, HybridSign
from quantum_safe.protocols.envelope import Envelope, SealedMessage
from quantum_safe.signatures import Sign
from quantum_safe.types import PublicKey, SecretKey
from quantum_safe.types.kem import CipherText, HybridCipherText
from quantum_safe.types.signatures import SignedMessage

pytestmark = pytest.mark.requires_liboqs

_DIR = pathlib.Path(__file__).parent / "vectors"
V = json.loads((_DIR / "ts_vectors.json").read_text(encoding="utf-8"))
JV = json.loads((_DIR / "ts_js_vectors.json").read_text(encoding="utf-8"))

TS_CONTEXT = b"ts-ctx"


def _ids(items, key="algorithm"):
    return [f"{i}-{x[key]}" for i, x in enumerate(items)]


def _sig_verifier(algo: str, hedged: bool) -> Sign | HybridSign:
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        if "+" in algo:
            classical, pqc = algo.split("+", 1)
            return HybridSign(classical=classical, pqc=pqc, hedged=hedged)
        return Sign(algo, hedged=hedged)


# ---------------------------------------------------------------------------
# Guards against vacuous passes
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("data", "section", "minimum"),
    [
        (V, "kem", 8),
        (V, "envelope", 5),
        (V, "keys", 8),
        (V, "signatures", 20),
        (JV, "jwt", 6),
        (JV, "envelope", 3),
        (JV, "upgrade_kem", 3),
        (JV, "upgrade_sign", 2),
    ],
)
def test_vector_counts(data, section: str, minimum: int) -> None:
    assert len(data.get(section, [])) >= minimum


def test_both_hedging_modes_are_present() -> None:
    modes = {s["hedged"] for s in V["signatures"]}
    assert modes == {True, False}


# ---------------------------------------------------------------------------
# Rust-core vectors
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("k", V["kem"], ids=_ids(V["kem"]))
def test_kem_decapsulates(k) -> None:
    algo = k["algorithm"]
    sk = SecretKey(raw=bytes.fromhex(k["secret_key"]), algorithm=algo)
    ct_bytes = bytes.fromhex(k["ciphertext"])
    if "+" in algo:
        classical, pqc = algo.split("+", 1)
        ss = HybridKEM(classical=classical, pqc=pqc).decapsulate(
            sk, HybridCipherText.from_bytes(ct_bytes, algo)
        )
    else:
        ss = KEM(algo).decapsulate(sk, CipherText(ct_bytes, algo))
    assert bytes(ss).hex() == k["shared_secret"]


@pytest.mark.parametrize("e", V["envelope"], ids=_ids(V["envelope"]))
def test_envelope_opens(e) -> None:
    sk = SecretKey(raw=bytes.fromhex(e["secret_key"]), algorithm=e["algorithm"])
    sealed = SealedMessage.from_bytes(bytes.fromhex(e["sealed"]))
    assert Envelope.open(sealed, sk).hex() == e["plaintext"]


@pytest.mark.parametrize("k", V["keys"], ids=_ids(V["keys"]))
def test_keys_load_in_every_format(k) -> None:
    pub = PublicKey.from_cbor(bytes.fromhex(k["public_cbor"]))
    sec = SecretKey.from_cbor(bytes.fromhex(k["secret_cbor"]))
    assert pub.raw_bytes.hex() == k["public_raw"]
    assert PublicKey.from_pem(k["public_pem"]).raw_bytes == pub.raw_bytes
    assert SecretKey.from_pem(k["secret_pem"]).raw_bytes == sec.raw_bytes
    assert PublicKey.from_jwk(k["public_jwk"]).raw_bytes == pub.raw_bytes
    assert pub.fingerprint() == k["fingerprint"]
    assert pub.algorithm == k["algorithm"]


@pytest.mark.parametrize(
    "s",
    V["signatures"],
    ids=[f"{i}-{s['algorithm']}-hedged={s['hedged']}" for i, s in enumerate(V["signatures"])],
)
def test_signed_message_verifies(s) -> None:
    algo = s["algorithm"]
    sm = SignedMessage.from_cbor(bytes.fromhex(s["signed_message"]))
    pub = PublicKey(raw=bytes.fromhex(s["public_key"]), algorithm=algo)
    _sig_verifier(algo, s["hedged"]).verify(sm, pub, context=TS_CONTEXT)
    assert sm.message == b"ts signed message"


# ---------------------------------------------------------------------------
# npm-package vectors
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("t", JV["jwt"], ids=_ids(JV["jwt"]))
def test_jwt_verifies(t) -> None:
    from quantum_safe.protocols.jwt import JWTVerifier

    pub = PublicKey(raw=bytes.fromhex(t["public_key"]), algorithm=t["algorithm"])
    claims = JWTVerifier(pub, issuer=t["issuer"]).verify(t["token"])
    assert claims.get("sub") == "ts-user" and claims.get("n") == 7


@pytest.mark.parametrize("e", JV["envelope"], ids=_ids(JV["envelope"]))
def test_facade_envelope_opens(e) -> None:
    sk = SecretKey(raw=bytes.fromhex(e["secret_key"]), algorithm=e["algorithm"])
    assert Envelope.open(SealedMessage.from_hex(e["sealed"]), sk).hex() == e["plaintext"]


@pytest.mark.parametrize("u", JV["upgrade_kem"], ids=_ids(JV["upgrade_kem"]))
def test_upgraded_kem_key_decapsulates(u) -> None:
    algo = u["algorithm"]
    classical, pqc = algo.split("+", 1)
    sk = SecretKey(raw=bytes.fromhex(u["secret_key"]), algorithm=algo)
    ct = HybridCipherText.from_bytes(bytes.fromhex(u["ciphertext"]), algo)
    ss = HybridKEM(classical=classical, pqc=pqc).decapsulate(sk, ct)
    assert bytes(ss).hex() == u["shared_secret"]
    classical_pub = bytes.fromhex(u["classical_public"])
    assert bytes.fromhex(u["public_key"])[2 : 2 + len(classical_pub)] == classical_pub


@pytest.mark.parametrize("u", JV["upgrade_sign"], ids=_ids(JV["upgrade_sign"]))
def test_upgraded_signing_key_verifies(u) -> None:
    algo = u["algorithm"]
    pub = PublicKey(raw=bytes.fromhex(u["public_key"]), algorithm=algo)
    sm = SignedMessage.from_cbor(bytes.fromhex(u["signed_message"]))
    # These vectors carry no hedged flag; quantum-safe-ts signs hedged by
    # default, which the 32-byte prefix confirms.
    assert sm.signature[0] == 32
    _sig_verifier(algo, True).verify(sm, pub, context=b"")
    assert sm.message == b"ts signs after upgrade"


def test_ts_migration_store_loads_and_py_continues_it() -> None:
    from quantum_safe.migrate import MigrationStateManager
    from quantum_safe.types import MigrationState

    store = {k: bytes.fromhex(v) for k, v in JV["migrate_store"]["entries"].items()}
    mgr = MigrationStateManager(store)
    assert mgr.get_current_state("ts-user-1") == MigrationState.PQC_PREFERRED
    assert mgr.get_current_state("ünï/slash") == MigrationState.HYBRID_TRANSITION
    history = mgr.get_history("ts-user-1")
    assert [r.to_state.value for r in history] == ["hybrid_transition", "pqc_preferred"]
    assert history[0].metadata == {"batch": 3}
    assert history[0].actor == "ts-job"
    mgr.transition(
        "ts-user-1", MigrationState.PQC_PREFERRED, MigrationState.PQC_ONLY, "ML-KEM-768", actor="py"
    )
    assert mgr.get_current_state("ts-user-1") == MigrationState.PQC_ONLY
    assert len(mgr.get_history("ts-user-1")) == 3


# ---------------------------------------------------------------------------
# Negative controls: the checks above must be able to fail
# ---------------------------------------------------------------------------


def test_negative_control_tampered_message_is_rejected() -> None:
    from quantum_safe.exceptions import VerificationError

    s0 = V["signatures"][0]
    sm = SignedMessage.from_cbor(bytes.fromhex(s0["signed_message"]))
    pub = PublicKey(raw=bytes.fromhex(s0["public_key"]), algorithm=s0["algorithm"])
    bad = SignedMessage(
        message=bytes([sm.message[0] ^ 1]) + sm.message[1:],
        signature=sm.signature,
        algorithm=sm.algorithm,
        context=sm.context,
    )
    with pytest.raises(VerificationError):
        _sig_verifier(s0["algorithm"], s0["hedged"]).verify(bad, pub, context=TS_CONTEXT)


def test_negative_control_wrong_mode_is_rejected() -> None:
    from quantum_safe.exceptions import VerificationError

    s = next(x for x in V["signatures"] if not x["hedged"])
    sm = SignedMessage.from_cbor(bytes.fromhex(s["signed_message"]))
    pub = PublicKey(raw=bytes.fromhex(s["public_key"]), algorithm=s["algorithm"])
    with pytest.raises(VerificationError):
        _sig_verifier(s["algorithm"], True).verify(sm, pub, context=TS_CONTEXT)
