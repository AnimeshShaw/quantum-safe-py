"""
ACVP known-answer conformance testing against NIST-published test vectors.

Run with::

    python tests/conformance/acvp_kat.py
    python tests/conformance/acvp_kat.py --save results/acvp_kat.json

What this establishes, and what it does not
-------------------------------------------
This runs the test cases NIST publishes in its ACVP-Server repository against
whichever ML-KEM/ML-DSA implementation the ``[liboqs]`` extra resolves to, and
reports how many produce the expected answer.

It is **not** a CAVP or CMVP validation. Those are performed by accredited
laboratories against the production ACVTS server and result in a certificate;
nothing here produces one, and the distinction matters for any reader operating
under CNSA 2.0, where compliance runs through validated modules. The honest
claim supported by this module is "answers NIST-issued ACVP vectors correctly",
which is strictly weaker than "validated" and strictly stronger than "the API
exists".

Scope: why only two of the six test types run
---------------------------------------------
ACVP splits these algorithms into test types. Some assume entry points a
high-level binding may not offer; liboqs turns out to expose more than expected,
so most of ML-KEM and the ML-DSA verification path are reachable:

======================  ========  ======================================
ACVP test type          Runnable  Reason
======================  ========  ======================================
ML-KEM keyGen           **yes**   generate_keypair_seed() accepts the
                                  64-byte d||z seed FIPS 203 keygen is
                                  defined over.
ML-KEM decapsulation    **yes**   Deterministic: (dk, c) -> k.
ML-KEM encapsulation    **yes**   Requires injecting m; reached through
                                  OQS_KEM_encaps_derand via ctypes rather
                                  than the Python binding.
ML-KEM key checks       no        No public key-validation entry point.
ML-DSA sigVer           **yes**   Deterministic, via verify_with_ctx_str
                                  so context-carrying cases are usable.
ML-DSA keyGen/sigGen    no        Requires seed or deterministic-mode
                                  control the API does not expose.
ML-DSA externalMu       no        Supplies mu rather than a message.
======================  ========  ======================================

The runnable types cover key expansion, the deterministic decapsulation path
(including the FIPS 203 implicit-rejection behaviour that malformed-ciphertext
cases exercise) and signature verification against both valid and invalid
signatures.

Interpreting negative cases
---------------------------
Many ACVP verification cases expect *rejection*. An implementation that rejects
everything agrees with all of them while being useless, so a single pass rate
conflates evidence of very different strength. This module counts cases that
expect acceptance separately from those that expect rejection, and treats a run
as meaningful only if both are present and both pass.

ML-DSA interface detection
--------------------------
FIPS 204 distinguishes an *external* interface, which prepends a domain
separator and context string to the message before signing, from the *internal*
one that signs the prepared message directly. ACVP publishes cases for both.
liboqs exposes only one of them, and which one is an interoperability-relevant
fact rather than something to assume, so the runner probes it and reports the
answer instead of hard-coding it. Cases for the other interface are then
reported as out of scope rather than as failures.

Reproducibility
---------------
Vectors are fetched from a pinned ACVP-Server commit (``ACVP_COMMIT``) and
cached under ``tests/conformance/_vectors/``. They are deliberately not
committed to this repository: the full set runs to tens of megabytes. Pinning
the commit rather than tracking master means a re-run reproduces the same
answers.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.request
from dataclasses import asdict, dataclass, field
from typing import Any

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "src"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "bench"))

# Pinned so results are reproducible. Bump deliberately, never silently.
ACVP_COMMIT = "975de31eb83d87039ec88934fdc47d8c312b892d"
ACVP_RAW = (
    f"https://raw.githubusercontent.com/usnistgov/ACVP-Server/{ACVP_COMMIT}/gen-val/json-files"
)

VECTOR_DIR = os.path.join(os.path.dirname(__file__), "_vectors")

# Only the suites containing runnable cases are fetched by default.
SUITES = {
    "ML-KEM-keyGen-FIPS203": ("prompt.json", "expectedResults.json"),
    "ML-KEM-encapDecap-FIPS203": ("prompt.json", "expectedResults.json"),
    "ML-DSA-sigVer-FIPS204": ("prompt.json", "expectedResults.json"),
}


@dataclass
class SuiteResult:
    """Outcome for one ACVP test type."""

    suite: str
    test_type: str
    accept_expected_total: int = 0
    accept_expected_passed: int = 0
    reject_expected_total: int = 0
    reject_expected_passed: int = 0
    out_of_scope: int = 0
    errors: int = 0
    failures: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    @property
    def total_run(self) -> int:
        return self.accept_expected_total + self.reject_expected_total

    @property
    def total_passed(self) -> int:
        return self.accept_expected_passed + self.reject_expected_passed

    # Set for suites whose cases demand an exact output rather than an
    # accept/reject verdict, where the accept/reject split does not apply.
    exact_answer: bool = False

    @property
    def runnable(self) -> bool:
        return self.total_run > 0

    @property
    def meaningful(self) -> bool:
        """Whether the cases that ran can evidence conformance.

        Exact-answer suites qualify on coverage alone. Verdict suites need cases
        of both polarities: agreement on rejection alone is satisfied by an
        implementation that rejects everything.
        """
        if not self.runnable:
            return False
        if self.exact_answer:
            return True
        return self.accept_expected_total > 0 and self.reject_expected_total > 0

    @property
    def conformant(self) -> bool:
        return self.runnable and self.total_passed == self.total_run and self.errors == 0

    def verdict(self) -> str:
        if not self.runnable:
            return "NO RUNNABLE CASES"
        if not self.conformant:
            return "FAIL"
        return "PASS" if self.meaningful else "PASS (weak: rejection cases only)"

    def __str__(self) -> str:
        return (
            f"  {self.suite} / {self.test_type:<14} "
            f"expected-answer {self.accept_expected_passed}/{self.accept_expected_total}  "
            f"expected-reject {self.reject_expected_passed}/{self.reject_expected_total}  "
            f"out-of-scope {self.out_of_scope:<4} "
            f"{self.verdict()}"
        )


def liboqs_available() -> bool:
    """Whether the [liboqs] extra is importable in this interpreter."""
    try:
        import oqs  # noqa: F401
    except Exception:
        return False
    return True


def _download(url: str, dest: str, attempts: int = 4, timeout: int = 300) -> None:
    """Fetch one file, retrying transient failures, writing atomically.

    Some of these files are several megabytes and the raw endpoint occasionally
    stalls mid-transfer. Writing to a temporary path and renaming on success
    keeps a truncated download from being cached and silently reused.
    """
    last: Exception | None = None
    for attempt in range(1, attempts + 1):
        try:
            with urllib.request.urlopen(url, timeout=timeout) as resp:  # noqa: S310
                data = resp.read()
            tmp = f"{dest}.part"
            with open(tmp, "wb") as fh:
                fh.write(data)
            json.loads(data.decode("utf-8"))  # reject a truncated body
            os.replace(tmp, dest)
            return
        except Exception as exc:  # noqa: BLE001 - retry any transport/parse failure
            last = exc
            print(f"    attempt {attempt}/{attempts} failed ({type(exc).__name__}); retrying")
            for stale in (f"{dest}.part",):
                if os.path.exists(stale):
                    os.remove(stale)
    raise RuntimeError(f"could not fetch {url}: {last}")


def fetch_vectors(force: bool = False) -> dict[str, dict[str, Any]]:
    """Download and cache the pinned vector files."""
    os.makedirs(VECTOR_DIR, exist_ok=True)
    loaded: dict[str, dict[str, Any]] = {}
    for suite, files in SUITES.items():
        loaded[suite] = {}
        for fname in files:
            local = os.path.join(VECTOR_DIR, f"{suite}__{fname}")
            if force or not os.path.exists(local):
                print(f"  fetching {suite}/{fname}")
                _download(f"{ACVP_RAW}/{suite}/{fname}", local)
            with open(local, encoding="utf-8") as fh:
                loaded[suite][fname.replace(".json", "")] = json.load(fh)
    return loaded


def _index_expected(expected: dict[str, Any]) -> dict[int, dict[str, Any]]:
    out: dict[int, dict[str, Any]] = {}
    for group in expected.get("testGroups", []):
        for test in group.get("tests", []):
            out[test["tcId"]] = test
    return out


def run_ml_kem_decap(prompt: dict[str, Any], expected: dict[str, Any]) -> SuiteResult:
    """Deterministic (dk, c) -> k cases, including implicit-rejection cases."""
    import oqs

    res = SuiteResult(suite="ML-KEM", test_type="decapsulation", exact_answer=True)
    exp = _index_expected(expected)
    enabled = set(oqs.get_enabled_kem_mechanisms())

    for group in prompt.get("testGroups", []):
        if group.get("function") != "decapsulation":
            continue
        alg = group["parameterSet"]
        if alg not in enabled:
            res.out_of_scope += len(group.get("tests", []))
            res.notes.append(f"{alg} not enabled in this liboqs build")
            continue
        for test in group.get("tests", []):
            want = (exp.get(test["tcId"], {}) or {}).get("k")
            if want is None:
                res.out_of_scope += 1
                continue
            # Every published decapsulation case expects a specific shared
            # secret, including the malformed-ciphertext cases, whose expected
            # value is the implicit-rejection output. Both are "accept" in the
            # sense that a specific answer is required.
            res.accept_expected_total += 1
            try:
                with oqs.KeyEncapsulation(alg, secret_key=bytes.fromhex(test["dk"])) as kem:
                    got = kem.decap_secret(bytes.fromhex(test["c"])).hex().upper()
            except Exception as exc:
                res.errors += 1
                res.failures.append(f"tc{test['tcId']} {alg}: {type(exc).__name__}: {exc}")
                continue
            if got == want.upper():
                res.accept_expected_passed += 1
            else:
                res.failures.append(
                    f"tc{test['tcId']} {alg}: expected {want[:24]}..., got {got[:24]}..."
                )

    res.notes.append(
        "Malformed-ciphertext cases are included; FIPS 203 requires a specific "
        "implicit-rejection value rather than an error, so these exercise the "
        "rejection path while still expecting an exact answer."
    )
    # Recorded as a single polarity on purpose: ACVP expresses decapsulation as
    # exact-answer cases, not accept/reject verdicts.
    res.notes.append(
        "ACVP models decapsulation as exact-answer cases, so the accept/reject "
        "split does not apply here; 'meaningful' is judged by coverage instead."
    )
    return res


def run_ml_kem_keygen(prompt: dict[str, Any], expected: dict[str, Any]) -> SuiteResult:
    """Seeded keygen: (d, z) -> (ek, dk).

    Runnable because liboqs exposes ``generate_keypair_seed``, which takes the
    64-byte ``d || z`` seed FIPS 203 keygen is defined over. This pins the exact
    key-expansion output rather than merely checking that keygen produces
    something of the right length.
    """
    import oqs

    res = SuiteResult(suite="ML-KEM", test_type="keyGen", exact_answer=True)
    exp = _index_expected(expected)
    enabled = set(oqs.get_enabled_kem_mechanisms())

    for group in prompt.get("testGroups", []):
        alg = group.get("parameterSet")
        tests = group.get("tests", [])
        if alg not in enabled:
            res.out_of_scope += len(tests)
            res.notes.append(f"{alg} not enabled in this liboqs build")
            continue
        for test in tests:
            want = exp.get(test["tcId"], {}) or {}
            if "ek" not in want or "dk" not in want:
                res.out_of_scope += 1
                continue
            res.accept_expected_total += 1
            try:
                seed = bytes.fromhex(test["d"]) + bytes.fromhex(test["z"])
                with oqs.KeyEncapsulation(alg) as kem:
                    got_ek = kem.generate_keypair_seed(seed).hex().upper()
                    got_dk = kem.export_secret_key().hex().upper()
            except Exception as exc:
                res.errors += 1
                res.failures.append(f"tc{test['tcId']} {alg}: {type(exc).__name__}: {exc}")
                continue
            if got_ek == want["ek"].upper() and got_dk == want["dk"].upper():
                res.accept_expected_passed += 1
            else:
                res.failures.append(
                    f"tc{test['tcId']} {alg}: ek match={got_ek == want['ek'].upper()}, "
                    f"dk match={got_dk == want['dk'].upper()}"
                )

    res.notes.append(
        "Both the encapsulation and decapsulation keys are compared, so the full "
        "key expansion is pinned rather than just the public half."
    )
    return res


def _encaps_derand_available() -> bool:
    """Whether liboqs exports the derandomised encapsulation entry point."""
    try:
        import oqs.oqs as core

        return hasattr(core._liboqs, "OQS_KEM_encaps_derand")
    except Exception:
        return False


def run_ml_kem_encaps(prompt: dict[str, Any], expected: dict[str, Any]) -> SuiteResult:
    """Derandomised encapsulation: (ek, m) -> (c, k).

    ACVP supplies the message ``m`` that FIPS 203 encapsulation would otherwise
    draw from its own RNG, so these cases are only runnable against an entry point
    that accepts it. The Python binding's ``encap_secret`` does not, but liboqs
    exports ``OQS_KEM_encaps_derand``, which we reach directly through ctypes.

    This deliberately steps past the high-level binding. That is the same move a
    dedicated ACVP harness makes, and it is worth being explicit that the
    conformance evidence for this test type comes from the C entry point rather
    than from the API an application would call.
    """
    import ctypes

    import oqs
    import oqs.oqs as core

    res = SuiteResult(suite="ML-KEM", test_type="encapsulation", exact_answer=True)
    exp = _index_expected(expected)
    enabled = set(oqs.get_enabled_kem_mechanisms())

    if not _encaps_derand_available():
        total = sum(
            len(g.get("tests", []))
            for g in prompt.get("testGroups", [])
            if g.get("function") == "encapsulation"
        )
        res.out_of_scope += total
        res.notes.append(
            "OQS_KEM_encaps_derand is not exported by this liboqs build, so the "
            "message m cannot be injected and these cases cannot run."
        )
        return res

    lib = core._liboqs
    fn = lib.OQS_KEM_encaps_derand
    fn.restype = ctypes.c_int
    ubyte_p = ctypes.POINTER(ctypes.c_ubyte)
    fn.argtypes = [ctypes.c_void_p, ubyte_p, ubyte_p, ubyte_p, ubyte_p]

    for group in prompt.get("testGroups", []):
        if group.get("function") != "encapsulation":
            continue
        alg = group.get("parameterSet")
        tests = group.get("tests", [])
        if alg not in enabled:
            res.out_of_scope += len(tests)
            continue
        for test in tests:
            want = exp.get(test["tcId"], {}) or {}
            if "c" not in want or "k" not in want:
                res.out_of_scope += 1
                continue
            res.accept_expected_total += 1
            try:
                with oqs.KeyEncapsulation(alg) as kem:
                    ct_buf = ctypes.create_string_buffer(kem.length_ciphertext)
                    ss_buf = ctypes.create_string_buffer(kem.length_shared_secret)
                    ek_buf = ctypes.create_string_buffer(bytes.fromhex(test["ek"]))
                    m_buf = ctypes.create_string_buffer(bytes.fromhex(test["m"]))
                    rc = fn(
                        kem._kem,
                        ctypes.cast(ct_buf, ubyte_p),
                        ctypes.cast(ss_buf, ubyte_p),
                        ctypes.cast(ek_buf, ubyte_p),
                        ctypes.cast(m_buf, ubyte_p),
                    )
                    got_ct = ct_buf.raw[: kem.length_ciphertext].hex().upper()
                    got_ss = ss_buf.raw[: kem.length_shared_secret].hex().upper()
                if rc != 0:
                    res.errors += 1
                    res.failures.append(f"tc{test['tcId']} {alg}: OQS_STATUS {rc}")
                    continue
            except Exception as exc:
                res.errors += 1
                res.failures.append(f"tc{test['tcId']} {alg}: {type(exc).__name__}: {exc}")
                continue
            if got_ct == want["c"].upper() and got_ss == want["k"].upper():
                res.accept_expected_passed += 1
            else:
                res.failures.append(
                    f"tc{test['tcId']} {alg}: ciphertext match="
                    f"{got_ct == want['c'].upper()}, secret match={got_ss == want['k'].upper()}"
                )

    res.notes.append(
        "Driven through OQS_KEM_encaps_derand via ctypes, not through the Python "
        "binding: the high-level encap_secret() draws its own randomness and "
        "cannot accept the ACVP-supplied m."
    )
    res.notes.append(
        "Both the ciphertext and the shared secret are compared, so the full "
        "encapsulation output is pinned."
    )
    return res


def detect_ml_dsa_interface(prompt: dict[str, Any], expected: dict[str, Any]) -> str:
    """Determine which FIPS 204 interface the installed implementation exposes.

    Returns ``"external"``, ``"internal"`` or ``"undeterminable"``. Decided on
    cases that expect *acceptance*: agreement on rejection is weak evidence,
    because an implementation that rejects everything agrees with all of them.

    Uses ``verify_with_ctx_str`` so that cases carrying a context string are
    usable. liboqs advertises this through ``sig_with_ctx_support``; without it
    every ACVP acceptance case would be unreachable, since all of them carry a
    non-empty context.
    """
    import oqs

    exp = _index_expected(expected)
    enabled = set(oqs.get_enabled_sig_mechanisms())
    score: dict[str, int] = {"external": 0, "internal": 0}

    for group in prompt.get("testGroups", []):
        alg = group.get("parameterSet")
        if alg not in enabled:
            continue
        iface = group.get("signatureInterface")
        if iface not in score:
            continue
        if group.get("preHash") == "preHash":
            continue  # HashML-DSA is a distinct algorithm
        if group.get("externalMu"):
            continue  # supplies mu, not a message; no such entry point here
        for test in group.get("tests", []):
            if "message" not in test:
                continue
            if not (exp.get(test["tcId"], {}) or {}).get("testPassed"):
                continue  # only acceptance cases discriminate
            if not _verify_case(alg, test):
                continue
            score[iface] += 1

    if score["external"] and not score["internal"]:
        return "external"
    if score["internal"] and not score["external"]:
        return "internal"
    return "undeterminable"


def _verify_case(alg: str, test: dict[str, Any]) -> bool:
    """Verify one sigVer case, routing through the context-aware entry point."""
    import oqs

    try:
        with oqs.Signature(alg) as ver:
            if getattr(ver, "sig_with_ctx_support", False):
                return bool(
                    ver.verify_with_ctx_str(
                        bytes.fromhex(test["message"]),
                        bytes.fromhex(test["signature"]),
                        bytes.fromhex(test.get("context", "")),
                        bytes.fromhex(test["pk"]),
                    )
                )
            if test.get("context"):
                raise RuntimeError("context supplied but implementation lacks context support")
            return bool(
                ver.verify(
                    bytes.fromhex(test["message"]),
                    bytes.fromhex(test["signature"]),
                    bytes.fromhex(test["pk"]),
                )
            )
    except Exception:
        # liboqs raises on some malformed signatures rather than returning
        # False. For a case expecting rejection that is the correct outcome,
        # reached by a different route; the caller compares against the
        # expected verdict either way.
        return False


def run_ml_dsa_sigver(
    prompt: dict[str, Any], expected: dict[str, Any], interface: str
) -> SuiteResult:
    """Deterministic (pk, msg, sig) -> bool cases for the detected interface."""
    import oqs

    res = SuiteResult(suite="ML-DSA", test_type="sigVer")
    exp = _index_expected(expected)
    enabled = set(oqs.get_enabled_sig_mechanisms())
    res.notes.append(f"Detected FIPS 204 interface: {interface}")

    for group in prompt.get("testGroups", []):
        alg = group.get("parameterSet")
        tests = group.get("tests", [])
        if alg not in enabled:
            res.out_of_scope += len(tests)
            continue
        if group.get("preHash") == "preHash":
            res.out_of_scope += len(tests)
            continue
        if group.get("externalMu"):
            # These groups supply mu (the pre-hashed message representative)
            # instead of a message. Verifying from mu is a distinct entry point
            # that this binding does not expose.
            res.out_of_scope += len(tests)
            continue
        if interface not in ("external", "internal") or (
            group.get("signatureInterface") != interface
        ):
            res.out_of_scope += len(tests)
            continue
        for test in tests:
            if "message" not in test:
                res.out_of_scope += 1
                continue
            want = (exp.get(test["tcId"], {}) or {}).get("testPassed")
            if want is None:
                res.out_of_scope += 1
                continue
            if want:
                res.accept_expected_total += 1
            else:
                res.reject_expected_total += 1
            got = _verify_case(alg, test)
            if got == want:
                if want:
                    res.accept_expected_passed += 1
                else:
                    res.reject_expected_passed += 1
            else:
                res.failures.append(f"tc{test['tcId']} {alg}: expected {want}, got {got}")

    res.notes.append(
        "Cases carrying a context string are run through verify_with_ctx_str; "
        "every ACVP acceptance case has a non-empty context, so without that "
        "entry point none of them would be reachable."
    )
    res.notes.append(
        "externalMu groups supply mu rather than a message and remain out of "
        "scope: verifying from mu is a separate entry point this binding does "
        "not expose."
    )
    return res


def run_all(save_json: str | None = None, force_fetch: bool = False) -> list[SuiteResult]:
    try:
        import oqs  # noqa: F401
    except Exception as exc:
        print(f"liboqs unavailable ({exc}); install the [liboqs] extra to run conformance tests.")
        return []

    print("=" * 96)
    print("ACVP KNOWN-ANSWER CONFORMANCE (NIST-published vectors)")
    print(f"ACVP-Server commit {ACVP_COMMIT[:12]}")
    print("NOT a CAVP/CMVP validation - see module docstring")
    print("=" * 96)

    vectors = fetch_vectors(force=force_fetch)
    results: list[SuiteResult] = []

    keygen = vectors["ML-KEM-keyGen-FIPS203"]
    results.append(run_ml_kem_keygen(keygen["prompt"], keygen["expectedResults"]))

    kem = vectors["ML-KEM-encapDecap-FIPS203"]
    results.append(run_ml_kem_encaps(kem["prompt"], kem["expectedResults"]))
    results.append(run_ml_kem_decap(kem["prompt"], kem["expectedResults"]))

    dsa = vectors["ML-DSA-sigVer-FIPS204"]
    iface = detect_ml_dsa_interface(dsa["prompt"], dsa["expectedResults"])
    results.append(run_ml_dsa_sigver(dsa["prompt"], dsa["expectedResults"], iface))

    print()
    for r in results:
        print(r)
        for note in r.notes:
            print(f"      note: {note}")
        for fail in r.failures[:5]:
            print(f"      FAIL: {fail}")
        if len(r.failures) > 5:
            print(f"      ... and {len(r.failures) - 5} more failures")
        print()

    ran = sum(r.total_run for r in results)
    ok = sum(r.total_passed for r in results)
    executed = [r for r in results if r.runnable]
    skipped_suites = [r for r in results if not r.runnable]

    print("=" * 96)
    print(f"{ok}/{ran} runnable ACVP cases produced the expected answer.")
    if executed and all(r.conformant for r in executed):
        print("Every runnable case passed, for these test types:")
        for r in executed:
            strength = "" if r.meaningful else "  (weak: rejection cases only)"
            print(f"  - {r.suite} {r.test_type}: {r.total_passed}/{r.total_run}{strength}")
        print("\nThis supports the claim that the implementation answers NIST-issued")
        print("ACVP vectors correctly for those paths. It is NOT a CAVP/CMVP validation")
        print("and must not be described as the implementation being 'validated'.")
    elif executed:
        print("At least one case did not match. Investigate before making any")
        print("conformance claim.")
    else:
        print("No test type produced runnable cases; no conformance claim is supported.")

    if skipped_suites:
        print("\nTest types with no runnable cases (a scope limit, not a failure):")
        for r in skipped_suites:
            print(f"  - {r.suite} {r.test_type}: {r.out_of_scope} cases out of scope")
    print("=" * 96)

    if save_json:
        os.makedirs(os.path.dirname(save_json) or ".", exist_ok=True)
        with open(save_json, "w", encoding="utf-8") as fh:
            json.dump(
                {
                    "acvp_commit": ACVP_COMMIT,
                    "is_cavp_validation": False,
                    "results": [asdict(r) for r in results],
                },
                fh,
                indent=2,
            )
        print(f"\nSaved to {save_json}")

    return results


def main() -> int:
    ap = argparse.ArgumentParser(description="Run NIST ACVP known-answer tests.")
    ap.add_argument("--save", type=str, default=None)
    ap.add_argument("--force-fetch", action="store_true")
    args = ap.parse_args()
    results = run_all(save_json=args.save, force_fetch=args.force_fetch)
    executed = [r for r in results if r.runnable]
    if not executed:
        # No runnable cases is a scope limit of the binding, not a conformance
        # failure, so it must not be reported as one.
        return 0
    return 0 if all(r.conformant for r in executed) else 1


if __name__ == "__main__":
    raise SystemExit(main())
