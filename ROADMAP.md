# HavenSignal Roadmap

This roadmap describes sequencing, not a promise of delivery dates.

HavenSignal enables sensitive capabilities only after the corresponding security evidence exists.

## Product direction

HavenSignal's initial product context is anonymous sensitive reporting for
universities and higher-education institutions.

The roadmap must not include e-commerce, Shopify, merchant, checkout, billing,
subscription, marketplace, app-store, SaaS-growth, or monetization goals. Work
that does not advance confidential anonymous disclosure, human guidance,
reporter anonymity, metadata minimization, operator accountability, controlled
institutional operation, or release safety is out of scope.

## Phase 0 — Security architecture and specification

**Status: substantially complete, with external/production gates still open.**

Goals:

- define project scope and non-goals;
- establish the threat model;
- define data lifecycle and trust boundaries;
- specify report and Response Note cryptography;
- specify recovery credentials;
- specify audit receipts and transparency;
- specify operator MFA and credential lifecycle;
- specify request/multipart admission;
- specify hostile-file sandbox and safe view;
- specify retention, deletion, emergency export, alerts, and workstation hardening;
- maintain traceability and a security test plan.

Exit condition: internal design approval does not substitute for independent review where required by the specifications.

## Phase 1 — Metadata-only Stage A

**Status: active.**

Goals:

- keep the reporter surface inert;
- implement metadata-only state models;
- enforce monotonic transitions;
- enforce report/lease/operation fencing;
- validate immutable bindings;
- maintain fail-closed persistence boundaries;
- produce real PostgreSQL concurrency evidence before enabling protected transition execution.

No reporter content, recovery credential, cryptographic key, or production protected workflow should be introduced merely to complete this phase.

## Phase 2 — Security-service proofs and independent review

Goals:

- Key Service production-equivalent non-resurrection proof of concept;
- PostgreSQL concurrency acceptance tests;
- audit-service protocol implementation and verification;
- alert-service durability/failure tests;
- WebAuthn step-up implementation and review;
- exact cryptographic artifact interoperability tests;
- sandbox artifact pinning and isolation tests;
- reverse-proxy/request-admission integration tests.

Exit condition: required independent reviews and production gates for each service are documented as satisfied.

## Phase 3 — Protected workflow integration

Goals:

- submission acceptance with bounded request handling;
- encrypted report storage;
- operator claim/open lifecycle;
- controlled content decryption;
- safe attachment rendering;
- one Response Note finalization;
- receipt-gated key destruction;
- reporter recovery of only the Response Note;
- retention and deletion jobs with failure recovery.

All sensitive operations remain fail-closed if required security dependencies are unavailable.

## Phase 4 — Deployment hardening and external assessment

Goals:

- production settings separated from development settings;
- reproducible deployment artifacts;
- hardened operator/admin/custodian workstation profiles;
- secrets and key-custody procedures;
- backup/restore/non-resurrection drills;
- independent security assessment;
- documented residual risks;
- incident response and release procedures.

## Phase 5 — Controlled pilot

Goals:

- limited pilot with a suitable organization;
- synthetic and controlled acceptance testing before real sensitive data;
- accessibility review;
- operator training;
- operational monitoring that does not collect reporter content;
- feedback on whether one-response human guidance solves the intended first-contact problem.

A pilot must not be presented as proof of absolute anonymity or safety.

## Phase 6 — First supported release

Goals:

- explicit supported deployment profile;
- signed/tagged release;
- reproducible release notes;
- documented upgrade and rollback procedures;
- public security support policy;
- clear list of guarantees and non-guarantees.

## Ongoing open-source work

Across all phases:

- maintain issues and milestones;
- review pull requests;
- keep dependencies current;
- preserve documentation/code traceability;
- add regression tests for every security bug;
- publish security advisories when appropriate;
- seek independent contributors and reviewers.
