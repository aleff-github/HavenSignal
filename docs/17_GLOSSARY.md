# 17 — Glossary

**Reporter / Segnalante**  
Anonymous person submitting a report. No account is required.

**Operator**  
Authenticated person authorized to process reports and produce a Response Note.

**Administrator**  
Historical generic term superseded by the more precise Application Administrator and Infrastructure / Key Custodian roles.

**Application Administrator**  
Authenticated role that manages operators/application configuration, reads authorized audit evidence, and receives alerts. Does not read reports, obtain DEKs, invoke arbitrary decrypt/unwrap, or impersonate operators.

**Infrastructure / Key Custodian**  
Separate trust role responsible for Key Service infrastructure, availability, live replication, and infrastructure-key lifecycle. Does not automatically become an operator, Application Administrator, audit reader, or report reader.

**Report**  
Submitted free text plus accepted attachments.

**Response Note**  
Exactly one plain-text response written by an operator and later retrieved by the reporter.

**Ticket ID**  
Random public/non-secret lookup identifier. Not sequential.

**Recovery Secret**  
High-entropy secret required with Ticket ID to retrieve the Response Note.

**DEK**  
Data Encryption Key. Independent per-report key protecting the report text and attachments.

**Report-DEK**  
The independent per-report DEK protecting original report text and accepted attachment bytes.

**Response-DEK**  
Independent revocable key protecting one Response Note. It is destroyed 72 hours after first successful read and is subject to non-resurrection requirements.

**CLAIM**  
Action by which an operator reserves a SEALED report before content disclosure.

**CLAIMED**  
State after CLAIM and before OPEN.

**OPEN**  
State in which one operator has a valid controlled processing lease and report content may be rendered.

**ReportLease**  
Persisted server-authoritative OPEN lease containing operator/report binding, random lease identifier, generation/fencing token, authoritative timestamps, and state/version.

**INTERRUPTED**  
State after an OPEN session ends unexpectedly or times out without finalization.

**FINALIZING**  
Persisted state for the idempotent, resumable protocol that stages a protected Response Note, destroys the Report-DEK, audits destruction, and only then publishes availability.

**RESPONSE_AVAILABLE**  
State observable to the reporter only after Report-DEK destruction has been durably confirmed and audited.

**RESPONSE DESTROYED**  
Response lifecycle condition after server-authoritative expiry denies further use, the Response-DEK is destroyed/non-resurrectable, recovery state is invalidated, and ciphertext cleanup is completed or retrying.

**SEALED**  
Encrypted report waiting for processing.

**CDR**  
Content Disarm & Reconstruction. Technique for producing safer representations of potentially risky document content.

**Cryptographic erase**  
Making encrypted data irrecoverable by securely destroying the key needed to decrypt it, subject to the guarantees/limitations of the key-management design.

**Emergency Export**  
Exceptional, audited, strongly authenticated creation of an encrypted persistent package containing original report material.

**Fail closed**  
Deny or stop a sensitive operation when a required security control is unavailable, rather than falling back to a weaker mode.

**Durable audit receipt**  
Verifiable evidence that the Audit Service durably accepted the required pre-action event before a disclosure, destruction, or export operation is authorized.

**StepUpAuthorization**  
Single-use, briefly valid, non-replayable authorization bound to operator, ticket, operation, nonce, expiry, and exact artifact digest where applicable.

**Fencing token / lease generation**  
Monotonically increasing value that prevents stale tabs, sessions, delayed requests, or retries from earlier OPEN periods from becoming valid again.
