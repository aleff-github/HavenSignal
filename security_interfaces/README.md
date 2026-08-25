# Security interface placeholders

This package contains only deny-by-default placeholders for security service
families whose concrete construction is still blocked by
`docs/12_OPEN_SECURITY_DECISIONS.md`.

The public method names identify capability families already approved in
`docs/19_SECURITY_SERVICE_INTERFACES.md`. They do not define request payloads,
wire formats, receipts, credentials, cryptographic representations, or
deployment topology.

Every call raises the same controlled `SecurityControlUnavailable` error. The
placeholders:

- never return a success value;
- never store plaintext or keys;
- never log caller input;
- never provide a development bypass;
- are not registered as a Django application;
- must not be replaced until the specific OPEN gate is approved and its
  negative/failure tests exist.
