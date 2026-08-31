# Internal submission workflow

This Django application contains only the metadata state machine approved in
`docs/20_SUBMISSION_ACCEPTANCE_PROTOCOL.md`.

It deliberately contains no HTTP view, URL, form, reporter data, attachment,
original filename, recovery credential, verifier, cryptographic key, audit
receipt, external-service adapter, reconciler, or administrator registration.
The internal UUID is not a browser attempt credential or public report ID.

The pure transition planner accepts only approved edges, computes exactly one
monotonic version increment, and obtains time from the server. Invalid states,
skipped/backward edges, terminal-state changes, and invalid versions fail with
one controlled error code.

There is deliberately no database transition executor: adding one before its
dependent audit, key, cryptographic, and storage gates are closed could permit
an unevidenced protected transition. This package does not authorize
submission. Multi-process concurrency and crash testing on PostgreSQL remains
a release gate before any endpoint or security-service edge can be enabled;
SQLite is only the local scaffold.

The initial migration is protected by a non-executing exact-AST policy. It
requires the sole reviewed numbered migration and fixes the empty dependency
graph, metadata-only fields, state/version constraints, and terminal timestamp
pairing. The scanner never imports or executes migration source; passing is
source-conformance evidence only and is not PostgreSQL or production proof.
