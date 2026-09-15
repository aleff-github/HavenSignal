"""Regenerate fixed public-test-key artifacts; no application imports or inputs."""

import argparse
import hashlib
import json
from pathlib import Path

import cbor2
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cwt import COSE, COSEKey


ROOT = Path(__file__).resolve().parent
CONTENT_TYPE = "application/vnd.anonymous-reporting.audit-acceptance+cbor;v=1"


def encode(value):
    # Only the fixed one-byte-label maps used below: length-first and RFC 8949
    # core ordering coincide here. This is not a generic core CBOR encoder.
    return cbor2.dumps(value, canonical=True)


def describe(value):
    if isinstance(value, bytes):
        return {"bytes": value.hex()}
    if type(value) is int and abs(value) > (1 << 53) - 1:
        return {"integer": str(value)}
    if isinstance(value, (list, tuple)):
        return [describe(item) for item in value]
    return value


def build():
    standard = json.loads((ROOT / "standards.json").read_text())["ed25519"][0]
    public = bytes.fromhex(standard["public_hex"])
    seed = bytes.fromhex(standard["seed_hex"])
    key = COSEKey.new({1: 1, 3: -8, -1: 6, -2: public, -4: seed})
    public_cose = encode({1: 1, -1: 6, -2: public})
    kid = hashlib.sha256(public_cose).digest()[:16]
    header = {1: -8, 3: CONTENT_TYPE, 4: kid}
    base_claims = [1, bytes(range(32)), bytes(range(16)), 0, b"\xaa" * 32,
                   1_700_000_000_000, 1_700_000_030_000]
    signed_artifacts = set()

    def sign(payload, phdr=None, uhdr=None, aad=b""):
        wire = COSE(deterministic_header=True).encode_and_sign(
            payload, key, protected=header if phdr is None else phdr,
            unprotected={} if uhdr is None else uhdr, external_aad=aad)
        if not aad:
            signed_artifacts.add(wire)
        return wire

    def sign_malformed(protected, payload, unprotected=None):
        # Deliberately bypass the COSE library's schema checks ONLY to create
        # invalid fixed test vectors with otherwise valid RFC 8032 signatures.
        signature_input = encode(["Signature1", protected, b"", payload])
        signature = Ed25519PrivateKey.from_private_bytes(seed).sign(signature_input)
        wire = encode(cbor2.CBORTag(18, [protected,
                      {} if unprotected is None else unprotected, payload, signature]))
        signed_artifacts.add(wire)
        return wire

    def record(identifier, wire, expected, claims, reason):
        return {"id": identifier, "receipt_hex": wire.hex(),
                "expected_wire_valid": expected, "expected_claims": describe(claims),
                "requires_valid_signature": wire in signed_artifacts,
                "reason": reason, "authorizes_protected_action": False}

    vectors = []
    for identifier, index, expiry in (("bounded-window", 0, base_claims[6]),
                                       ("historical-null-window", 24, None),
                                       ("uint64-index", (1 << 64) - 1, None)):
        claims = list(base_claims)
        claims[3], claims[6] = index, expiry
        wire = sign(encode(claims))
        tagged = cbor2.loads(wire)
        item = record(identifier, wire, True, claims, "wire syntax and fixture binding only")
        item.update(protected_hex=tagged.value[0].hex(), payload_hex=tagged.value[2].hex(),
                    signature_input_hex=encode(["Signature1", tagged.value[0], b"", tagged.value[2]]).hex())
        vectors.append(item)

    baseline = bytes.fromhex(vectors[0]["receipt_hex"])
    body = list(cbor2.loads(baseline).value)

    def invalid(identifier, wire, reason, claims=None):
        vectors.append(record(identifier, wire, False,
                              base_claims if claims is None else claims, reason))

    def envelope(parts, tag=18):
        return encode(cbor2.CBORTag(tag, parts))

    invalid("missing-tag", encode(body), "tag 18 required")
    invalid("wrong-tag", envelope(body, 17), "exact COSE_Sign1 tag required")
    invalid("trailing-item", baseline + b"\x00", "exactly one CBOR item")
    invalid("nonminimal-tag", b"\xd8\x12" + baseline[1:], "nonminimal tag encoding")
    invalid("indefinite-envelope", b"\xd2\x9f" + baseline[2:] + b"\xff", "indefinite array")
    invalid("extra-envelope-field", envelope(body + [None]), "exactly four fields")
    invalid("truncated", baseline[:-1], "truncated signature")
    invalid("oversized", baseline + b"\x00" * 2048, "bounded proof parser")
    changed = list(body)
    changed[3] = bytes([body[3][0] ^ 1]) + body[3][1:]
    invalid("altered-signature", envelope(changed), "signature verification")
    changed[3] = body[3][:-1]
    invalid("short-signature", envelope(changed), "exact signature length")
    # RFC 8032 requires S < L; this test is deliberately signed-scalar malleation.
    order = (1 << 252) + 27742317777372353535851937790883648493
    changed[3] = body[3][:32] + (int.from_bytes(body[3][32:], "little") + order).to_bytes(32, "little")
    invalid("noncanonical-signature-s", envelope(changed), "RFC 8032 scalar range")
    invalid("nonempty-unprotected", sign_malformed(body[0], body[2], {4: kid}), "empty unprotected map required")
    invalid("nonempty-external-aad", sign(body[2], aad=b"PUBLIC-TEST"), "external AAD must be empty")
    invalid("wrong-content-type", sign(body[2], {1: -8, 3: "TEST", 4: kid}), "exact content type")
    invalid("wrong-kid", sign(body[2], {1: -8, 3: CONTENT_TYPE, 4: b"\xff" * 16}), "fixture-selected key binding")
    invalid("unknown-protected-header", sign_malformed(encode({**header, 42: 1}), body[2]), "closed header set")
    headers = cbor2.loads(body[0])
    for identifier, protected in (
        ("wrong-algorithm", encode({**headers, 1: -7})),
        ("duplicate-header", b"\xa4" + body[0][1:] + encode(1) + encode(-8)),
        ("nonminimal-protected-map", b"\xb8\x03" + body[0][1:]),
        ("reordered-protected-map", cbor2.dumps(dict(reversed(list(headers.items()))))),
        ("trailing-protected-item", body[0] + b"\x00"),
    ):
        # Re-sign exact alternate bytes: schema/canonical checks, not accidental
        # signature breakage, must reject these artifacts.
        invalid(identifier, sign_malformed(protected, body[2]), "exact deterministic protected header map")

    for identifier, position, value in (
        ("boolean-version", 0, True), ("unknown-version", 0, 2),
        ("short-log-id", 1, b"\x00" * 31), ("text-event-id", 2, "0" * 16),
        ("negative-index", 3, -1), ("boolean-index", 3, True),
        ("bignum-index", 3, 1 << 64), ("float-time", 5, 1.5),
        ("expiry-before-acceptance", 6, base_claims[5] - 1),
    ):
        claims = list(base_claims)
        claims[position] = value
        invalid(identifier, sign(encode(claims)), "signed malformed claim field")
    invalid("extra-claim", sign(encode(base_claims + [None])), "exactly seven claims")
    invalid("nonminimal-payload-version", sign(b"\x87\x18\x01" + body[2][2:]), "signed nonminimal integer")
    invalid("indefinite-payload", sign(b"\x9f" + body[2][1:] + b"\xff"), "signed indefinite payload")
    invalid("trailing-payload-item", sign(body[2] + b"\x00"), "one signed payload item")
    for identifier, position, value in (
        ("mismatched-event", 2, b"\xbb" * 16),
        ("mismatched-leaf-hash", 4, b"\xbb" * 32),
        ("mismatched-expiry", 6, base_claims[6] + 1),
    ):
        expected = list(base_claims)
        expected[position] = value
        invalid(identifier, baseline, "valid signature, wrong expected fixture context", expected)
    return {"format": "havensignal-offline-audit-wire-v1", "public_test_key": standard["id"],
            "public_key_hex": public.hex(), "public_cose_key_hex": public_cose.hex(),
            "kid_hex": kid.hex(), "content_type": CONTENT_TYPE, "vectors": vectors}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write", action="store_true", help="replace only the fixed synthetic corpus")
    args = parser.parse_args()
    expected = json.dumps(build(), indent=2) + "\n"
    path = ROOT / "vectors.json"
    if args.write:
        path.write_text(expected)
    elif not path.exists() or path.read_text() != expected:
        raise SystemExit("audit_vector_corpus_drift")
    print("audit vector regeneration: PASS")


if __name__ == "__main__":
    main()
