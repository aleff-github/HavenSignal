# Offline Audit v1 wire interoperability proof

Status: **bounded wire-format proof passed on 2026-09-15**. This is the first
executable slice of P2-02 in the
[security-service work packet](../../docs/SECURITY_SERVICE_REVIEW_PACKET.md).
It is not an Audit Service, durable receipt issuer, receipt authorization
verifier, cryptographic review, or production library selection.

## Reproduce

Run with Python 3.13 and Node 22 from this directory:

```sh
python3.13 -m venv .venv
.venv/bin/python -m pip install --require-hashes -r requirements.lock
npm ci --ignore-scripts --no-audit --no-fund
.venv/bin/python build_vectors.py
.venv/bin/python verify_python.py
node verify.mjs
```

Installation downloads dependencies. After installation, the three proof
commands operate only on the checked-in fixtures, without database, network,
environment credentials, application imports, or service calls. Each command
must exit 0. The dedicated `audit-vectors` CI job runs this exact sequence;
native and PostgreSQL application verification remain separate jobs.

`build_vectors.py` checks byte-for-byte regeneration by default. Only the
explicit `--write` option rewrites `vectors.json`. Intentional corpus changes
require review, both independent verifiers, and updated manifest hashes.

## Evidence and exact limits

| Corpus | Cases | Observation |
|---|---:|---|
| RFC 8949 Appendix A subset | 16 | Both libraries reproduce the published integer, byte/text string, boolean, null, and array bytes. |
| RFC 8032 section 7.1, tests 1 and 2 | 2 | Both cryptographic implementations reproduce public keys and exact signatures and verify them. |
| Published COSE WG Ed25519 Sign1 example | 1 | Both verify its signature; both reject it as a HavenSignal receipt. |
| Synthetic acceptance-receipt wire profile | 3 positive, 37 negative | Both agree on exact bytes and rejection outcomes. JavaScript also independently recreates every positive receipt and signature. |

Python uses Python CWT's COSE API, cbor2, and cryptography's Ed25519. The
independent implementation uses node-cbor plus noble's JavaScript Ed25519 with
`zip215: false`. It constructs the standard RFC 9052 `Sig_structure` and calls
the library; neither verifier implements curve arithmetic. The implementations
share frozen fixtures and the normative profile, not parsing or signing code.
Agreement is interoperability evidence, not independent security review.

Negative fixtures cover missing/wrong/nonminimal tags, extra/truncated/trailing
data, indefinite containers, duplicate/reordered/unknown headers, wrong key ID,
algorithm or content type, nonempty unprotected headers or external AAD,
signature alteration/length/noncanonical S, incorrect claim types/lengths,
uint64 overflow, nonminimal integers, invalid expiry ordering, and mismatched
expected event/hash/expiry. Where a malformed fixture deliberately has a valid
signature, both verifiers assert that separately before requiring rejection.
This prevents accidental signature damage from masking a missing schema check.

The synthetic claims use fixed internal test bytes, a fixed timestamp, and a
dummy leaf hash. They are not receipts for committed events. The proof compares
their expected fixture context but does not recompute a real event leaf hash,
validate event profiles, look up trusted keys, check current time/lease/state,
consume replay keys, or authorize any protected operation. The 2,048-byte proof
parser bound is a local test limit, not a newly approved service input limit.

## Format questions kept open

- The positive COSE maps use only one-byte integer labels, for which legacy
  length-first and RFC 8949 core map ordering coincide. The use of
  `canonical=True` / `encodeCanonical` is limited to this subset. It is not
  evidence for arbitrary-map core deterministic CBOR; codecs must be reviewed
  again before adding another map profile.
- This corpus uses an explicitly fixed minimal public COSE Key map containing
  only `kty`, `crv`, and `x` to derive its fixture `kid`. Docs/23 does not yet
  fix optional public-key parameters for that hash. The production public-key
  serialization must be specified; this fixture choice does not decide it.
- Event/caller/operation registries, contextual authorization windows,
  checkpoint/RFC 9942 content types, clock skew, checkpoint and proof vectors,
  and independent review remain open. The full Phase 2 interoperability item
  therefore remains unchecked.

## Dependency assessment and isolation

Direct proof pins are Python CWT 3.3.0, cbor2 5.9.0, cryptography 50.0.1,
node-cbor 10.0.12, and noble-curves 2.4.0. Python transitive versions/artifact
hashes and npm versions/integrities are committed in the two lock files.
They are lab tools, not approved production dependencies. Python CWT declares
cbor2 below version 6; the lock respects that compatibility boundary.

The initial pycose candidate was removed after its dependency chain reported
the python-ecdsa [Minerva advisory](https://github.com/tlsfuzzer/python-ecdsa/security/advisories/GHSA-wj6h-64fc-37mp)
and its general decoder proved incompatible with cbor2 6. The final lock
contains neither pycose nor python-ecdsa. The replacement lock was checked with
`pip-audit` and npm's lock with `npm audit`: no known advisories were reported
on 2026-09-14. This is a dated database check, not a security guarantee.

Before changing proof dependencies, review upstream releases/advisories,
regenerate both relevant locks, run the corpus through both implementations,
and repeat vulnerability checks. No automatic dependency substitution occurs
during proof execution. Relevant upstream projects are
[Python CWT](https://github.com/dajiaji/python-cwt),
[cbor2](https://github.com/agronholm/cbor2),
[cryptography](https://github.com/pyca/cryptography),
[node-cbor](https://github.com/hildjj/node-cbor), and
[noble-curves](https://github.com/paulmillr/noble-curves).

The application dependencies and unavailable adapters are unchanged. `proofs`
is excluded from the Docker build context, and native tests check for static
proof-library imports into application packages and accidental proof dependency
inclusion. These source checks are not a claim of runtime sandbox isolation.

## Public fixture provenance

`standards.json` identifies [RFC 8949 Appendix A](https://www.rfc-editor.org/rfc/rfc8949.html#appendix-A),
[RFC 8032 section 7.1](https://www.rfc-editor.org/rfc/rfc8032.html#section-7.1),
and the [COSE WG example at its fixed source commit](https://github.com/cose-wg/Examples/blob/53c9d634333bb4f529d78f5980fffa2667ee2c12/eddsa-examples/eddsa-sig-01.json).
RFC-derived test data is attributed to the IETF Trust and the document authors;
see [the notice](NOTICE.md). The COSE WG example is distributed under the
[Unlicense](https://github.com/cose-wg/Examples/blob/53c9d634333bb4f529d78f5980fffa2667ee2c12/LICENSE).

The Ed25519 seeds are deliberately public RFC test values. They protect
nothing, must never be reused outside this corpus, and are not generated from
or substituted with any application's credentials. No real report, recovery
secret, production key, token, or reporter-controlled material is present.
