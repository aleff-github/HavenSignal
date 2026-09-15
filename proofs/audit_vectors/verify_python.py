"""Check fixed offline fixtures with cbor2, Python CWT and cryptography only."""

import hashlib
import json
from collections.abc import Mapping
from pathlib import Path

import cbor2
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cwt import COSE, COSEKey, DecodeError, VerifyError


ROOT = Path(__file__).resolve().parent
CONTENT_TYPE = "application/vnd.anonymous-reporting.audit-acceptance+cbor;v=1"
MAX_UINT = (1 << 64) - 1


def semantic(value):
    if type(value) is dict:
        if set(value) == {"bytes"}:
            return bytes.fromhex(value["bytes"])
        if set(value) == {"integer"}:
            return int(value["integer"])
        raise ValueError("unknown_fixture_shape")
    if type(value) is list:
        return [semantic(item) for item in value]
    return value


def encode(value):
    # Fixed profile subset only; see README for map-ordering limitations.
    return cbor2.dumps(value, canonical=True)


def uint(value):
    return type(value) is int and 0 <= value <= MAX_UINT


def octets(value, size):
    return type(value) is bytes and len(value) == size


def wire_matches_fixture(raw, public, kid, expected):
    """Syntax/signature/fixture binding only. NEVER an authorization decision."""
    try:
        if not 0 < len(raw) <= 2048:
            return False
        tagged = cbor2.loads(raw)
        if not isinstance(tagged, cbor2.CBORTag) or tagged.tag != 18:
            return False
        body = tagged.value
        if not isinstance(body, (list, tuple)) or len(body) != 4:
            return False
        protected, unprotected, payload, signature = body
        if (type(protected) is not bytes or type(payload) is not bytes
                or not isinstance(unprotected, Mapping) or len(unprotected) != 0
                or not octets(signature, 64) or encode(tagged) != raw):
            return False
        headers = cbor2.loads(protected)
        if (type(headers) is not dict or set(headers) != {1, 3, 4}
                or any(type(label) is not int for label in headers)
                or type(headers[1]) is not int or headers[1] != -8
                or headers[3] != CONTENT_TYPE or not octets(headers[4], 16)
                or headers[4] != kid or encode(headers) != protected):
            return False
        claims = cbor2.loads(payload)
        if type(claims) is not list or len(claims) != 7:
            return False
        if (type(claims[0]) is not int or claims[0] != 1
                or not octets(claims[1], 32) or not octets(claims[2], 16)
                or not uint(claims[3]) or not octets(claims[4], 32)
                or not uint(claims[5])
                or not (claims[6] is None or (uint(claims[6]) and claims[6] >= claims[5]))
                or encode(claims) != payload or encode(expected) != payload):
            return False
        key = COSEKey.new({1: 1, 2: kid, 3: -8, -1: 6, -2: public})
        return COSE(verify_kid=True).decode(raw, key) == payload
    except (ValueError, TypeError, KeyError, cbor2.CBORDecodeError, DecodeError, VerifyError):
        return False


def check(condition, label):
    if not condition:
        raise AssertionError(label)


def main():
    standard = json.loads((ROOT / "standards.json").read_text())
    for case in standard["cbor"]:
        raw = bytes.fromhex(case["hex"])
        check(encode(semantic(case["value"])) == raw, case["id"])
        check(encode(cbor2.loads(raw)) == raw, case["id"])
    for case in standard["ed25519"]:
        private = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(case["seed_hex"]))
        public = private.public_key()
        check(public.public_bytes_raw().hex() == case["public_hex"], case["id"])
        message = bytes.fromhex(case["message_hex"])
        signature = bytes.fromhex(case["signature_hex"])
        check(private.sign(message) == signature, case["id"])
        public.verify(signature, message)

    corpus = json.loads((ROOT / "vectors.json").read_text())
    public = bytes.fromhex(standard["ed25519"][0]["public_hex"])
    public_cose = encode({1: 1, -1: 6, -2: public})
    kid = hashlib.sha256(public_cose).digest()[:16]
    published = standard["cose_wg"]
    raw = bytes.fromhex(published["receipt_hex"])
    body = cbor2.loads(raw).value
    check(encode(["Signature1", body[0], b"", body[2]]).hex()
          == published["signature_input_hex"], published["id"])
    published_key = COSEKey.new({1: 1, 2: b"11", 3: -8, -1: 6, -2: public})
    check(COSE().decode(raw, published_key).hex() == published["message_hex"], published["id"])
    check(not wire_matches_fixture(raw, public, kid, []), "generic_cose_is_not_audit")
    check(corpus["format"] == "havensignal-offline-audit-wire-v1", "format")
    check(corpus["public_key_hex"] == public.hex(), "public_key")
    check(corpus["public_cose_key_hex"] == public_cose.hex(), "public_cose_key")
    check(corpus["kid_hex"] == kid.hex(), "kid")
    check(corpus["content_type"] == CONTENT_TYPE, "content_type")
    check(len(corpus["vectors"]) > 3, "nonempty_negative_corpus")
    for case in corpus["vectors"]:
        raw = bytes.fromhex(case["receipt_hex"])
        check(type(case["expected_wire_valid"]) is bool, "expected_boolean")
        check(case["authorizes_protected_action"] is False, "no_authority")
        if case["requires_valid_signature"]:
            # Malformed but correctly signed cases must fail on profile checks,
            # not because the generator accidentally broke their signatures.
            body = cbor2.loads(raw).value
            Ed25519PublicKey.from_public_bytes(public).verify(
                body[3], encode(["Signature1", body[0], b"", body[2]]))
        check(wire_matches_fixture(raw, public, kid, semantic(case["expected_claims"]))
              is case["expected_wire_valid"], case["id"])
        if case["expected_wire_valid"]:
            body = cbor2.loads(raw).value
            check(body[0].hex() == case["protected_hex"], case["id"])
            check(body[2].hex() == case["payload_hex"], case["id"])
            check(encode(["Signature1", body[0], b"", body[2]]).hex()
                  == case["signature_input_hex"], case["id"])
    print(f"Python: PASS ({len(standard['cbor'])} CBOR, {len(standard['ed25519'])} Ed25519, 1 published COSE, "
          f"{len(corpus['vectors'])} receipt cases; no authorization)")


if __name__ == "__main__":
    main()
