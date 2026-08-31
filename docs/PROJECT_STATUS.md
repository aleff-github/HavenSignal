# Current Project Status

**Status: security-first pre-alpha / metadata-only implementation stage.**

This document keeps the implementation boundary visible without requiring the top-level README to reproduce the full handoff narrative.

## Reporter surface

The repository contains a Django 5.2.17 development scaffold and one inert, read-only reporter landing page.

The page has no:

- submission form;
- JavaScript;
- analytics;
- third-party resources;
- report storage;
- authentication;
- production business logic.

The current surface must not be used for real sensitive reports.

## Submission workflow

`submission_workflow/` defines only the approved attempt states, database shape, constraints, and a pure monotonic transition planner.

It has no public submission endpoint or database transition executor and stores no reporter content, credential, key, verifier, filename, request metadata, or audit receipt.

## Report lifecycle

`report_lifecycle/` implements the owner-authorized inert Stage A for metadata-only `Report`, `ReportLease`, and `SecurityOperation` concepts.

It includes:

- explicit state edges;
- monotonically versioned pure planners;
- server-time lease validation;
- database constraints;
- immutable binding validation;
- stale-version/stale-generation/wrong-lease/expired-lease rejection;
- a fail-closed persistence boundary.
- pure, non-persisting sequence contracts for the approved finalization order
  and OPEN-only operator-deletion order;
- pure planners for Response Note retention, ciphertext-cleanup retry timing,
  terminal-metadata retention review, and isolated audit-retention review.

SQLite remains a development/test scaffold and is not accepted as evidence for security-sensitive concurrency.

A test-only PostgreSQL concurrency scaffold exists, but it is not itself PostgreSQL acceptance evidence and does not enable protected transition execution.

## Security interfaces

Mandatory security integrations whose production designs or evidence remain gated are represented by deny-by-default interfaces under `security_interfaces/`.

Unavailable operations fail explicitly rather than providing weaker fallbacks.
Their controlled errors and unavailable adapters are also locked by a
non-executing exact-AST policy, so a success path, development fallback, added
method, logging operation, or other side effect requires explicit review.

The package includes inert structural descriptors for approved audit, alert, and step-up concepts, but these types do not themselves:

- encode/verify production audit artifacts;
- append audit events;
- send alerts;
- persist alert delivery;
- perform WebAuthn;
- create or verify production step-up authorization artifacts;
- authorize protected operations.

The administrative step-up-v2 foundations are limited to content-free internal
identity shapes, binding-purpose/key-epoch metadata, the exact non-sliding
120-second lifetime, and an unused-only state. Operation, target and artifact
registries, WebAuthn material, binding bytes, persistence, consumption and all
authorization capabilities remain absent.

## Architecture checks

`architecture_checks/` statically constrains the current Reporter Gateway and
root URL surface, including import allowlists, passive page expectations, and
the exact executable AST of the read-only view and restrictive response-header
middleware.

The same package statically locks the initial lifecycle migration and the inert
finalization, operator-deletion and retention planners to closed imports,
members, immutable metadata-only fields, false capability flags and
always-unavailable executors. Scanned target modules are parsed but never
imported or executed.

It also locks the administrative step-up-v2 descriptor to its exact imports,
constants, immutable classes, validators, and closed call profile without
executing the descriptor source.

The audit-v1 descriptor module is likewise locked to its complete reviewed
executable AST. Registry, field, validator, authorization-window, success-return,
import, dynamic, or side-effect changes require an explicit policy update; the
target is never imported or executed by the check.

The alert-v1 descriptors have the same non-executing exact-AST guard. Their
fixed registries, content-free fields, validators and false durability and
authorization results cannot change without an explicit policy update.

The report-bound step-up-v1 descriptor module is also locked to its complete
reviewed executable AST, including timing, registries, content-free context,
unused state, validators, and false WebAuthn/binding/authorization results.

The controlled security-interface errors and unavailable external-service
adapters are likewise parsed but never imported or executed and must retain
their exact generic fail-closed behavior.

These checks are review guards, not production network/process security boundaries.

## Approved designs versus enabled capability

The repository contains detailed approved protocol documents covering areas including:

- submission acceptance;
- recovery credentials;
- self-hosted no-JavaScript challenge;
- audit receipts and transparency;
- Response Note cryptography;
- MFA step-up;
- report-content cryptography;
- Key Service non-resurrection testing;
- emergency export;
- file acceptance/sandbox/safe view;
- request and multipart admission;
- administrator alerts;
- retention/deletion;
- operational access and workstation hardening.

Approval of a design document does **not** mean its protected workflow is enabled.

`docs/34_PRE_CODE_SECURITY_GATE.md` authorizes only the bounded metadata-only Stage A and preserves external, independent-review, and production gates.

## Not currently implemented as production capability

The repository does not currently provide a production-ready:

- report submission workflow;
- report plaintext storage/decryption flow;
- reporter recovery flow;
- operator authentication flow;
- file-processing service;
- audit service;
- alert service;
- Key Service;
- emergency export workflow;
- retention/deletion executor;
- background job system;
- production deployment profile.

## Development commands

```bash
python manage.py check
python manage.py test -v 2
python manage.py runserver 127.0.0.1:8000
```

The development server is for local testing only.
