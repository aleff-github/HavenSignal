# 15 — Deployment Trust Boundaries

This is a conceptual decomposition, not a final deployment diagram.

## Boundary A — Reporter Edge

Responsibilities:

- serve reporter form;
- CAPTCHA challenge;
- accept submission;
- enforce size/input limits;
- forward accepted data into encryption/storage pipeline.

Must not have:

- audit-history mutation capability;
- administrator capabilities;
- unnecessary long-lived report-decryption authority;
- a general `decrypt_report` or `unwrap_any_DEK` capability for existing reports.

Key Service capabilities available to this boundary are role-scoped, operation-scoped, report-scoped where applicable, state-aware, and server-authoritative.

## Boundary B — Report Metadata / Ciphertext Store

Candidate:

- PostgreSQL for metadata;
- encrypted blob/object/filesystem storage for attachment ciphertext.

Must not contain sufficient plaintext key material to decrypt reports on its own.

## Boundary C — Key Service

Responsibilities:

- protect/wrap/authorize report-key use;
- enforce lifecycle as approved;
- support cryptographic deletion/non-resurrection.

Active per-object DEKs may use live replication inside this boundary. Historical backups/snapshots capable of resurrecting destroyed Report-DEKs or Response-DEKs are forbidden.

Must be operationally separated from ordinary report storage.

## Boundary D — File Processing Sandbox

Responsibilities:

- validate untrusted PDF/JPEG/PNG;
- reject active/unsafe material;
- create safe temporary operator viewing representations.

Must not have:

- general network access;
- broad filesystem access;
- admin/audit credentials;
- long-lived production secrets.

Plaintext temporary-workspace creation, access, crash cleanup, timeout cleanup, and deletion must be explicit and testable.

## Boundary E — Operator Console

Responsibilities:

- operator authentication;
- CLAIM/OPEN/reopen lifecycle;
- controlled viewing;
- Response Note creation;
- emergency export initiation.

OPEN/REOPEN decryption requires the valid current ReportLease generation and applicable durable pre-action audit receipt.

Must not have audit-history mutation permission.

## Boundary F — Application Administrator Console

Responsibilities:

- operator/account administration;
- configuration;
- audit review;
- anomaly review.

Must not provide report-decryption capability.

Must not permit operator impersonation through enrollment, reset, recovery, or session functions.

## Boundary G — Audit Collector / Store

Responsibilities:

- receive structured events;
- preserve append-only/tamper-evident history;
- provide administrator read access;
- detect gaps/failures.

Application should not have UPDATE/DELETE rights.

The collector returns durable pre-action receipts and must detect alteration, gaps, truncation, and cessation. Signed checkpoints or equivalent evidence must be independently verifiable.

## Boundary H — Emergency Export Key Domain

Organization public key may be available to the application for encryption.

Corresponding private key should not be routinely present in the web application environment.

## Boundary I — Infrastructure / Key Custodian

Responsibilities:

- Key Service infrastructure availability and live replication;
- infrastructure-key lifecycle;
- approved non-resurrection testing and operational procedure.

This role is not automatically an Operator, Application Administrator, audit reader, or report reader.

## Complete infrastructure compromise boundary

The baseline does not promise protection from one adversary simultaneously controlling application/operator-console code and deployment, operator credentials, and Key Service control. This limitation must not be used to collapse the normal role boundaries above.

## Network exposure

Reporter:

- Tor Onion Service;
- conventional HTTPS.

Operator:

- reachable from Internet per current requirement;
- therefore strong MFA, hardened session security, rate protection, and security headers are mandatory.

Administrator:

- access model to be hardened; exact network restrictions remain an implementation decision.
