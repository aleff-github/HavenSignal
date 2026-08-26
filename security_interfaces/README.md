# Security interface placeholders

This package contains only deny-by-default placeholders for security service
families whose concrete construction is still blocked by
`docs/12_OPEN_SECURITY_DECISIONS.md`.

The public method names identify capability families already approved in
`docs/19_SECURITY_SERVICE_INTERFACES.md`. `audit_descriptors.py` additionally
models only the closed event/actor names, exact replay-field lengths, and
acceptance-claim lifetimes already fixed by `docs/23`. It intentionally does
not define the still-incomplete per-event request profiles, wire encodings,
credentials, cryptographic verification, or deployment topology.

Every call raises the same controlled `SecurityControlUnavailable` error. The
placeholders:

- never return a success value;
- never store plaintext or keys;
- never log caller input;
- never provide a development bypass;
- are not registered as a Django application;
- must not be replaced until the specific OPEN gate is approved and its
  negative/failure tests exist.

A structurally valid acceptance-claims object is not a verified receipt and
always reports that it cannot authorize a protected action. CBOR encoding,
COSE parsing/signature verification, event append, durable commit, receipt
release, and all protected consumers remain absent. The context-dependent
`REPORT_KEY_DESTROYED` authorization lifetime is rejected until its exact
operation profile is closed rather than guessed.
