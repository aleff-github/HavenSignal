# Architecture checks

This package contains static, non-executing checks for the current inert
dependency boundaries. It is not a runtime sandbox, credential boundary, or
substitute for process/network isolation.

The reporter policy is an exact allowlist of imports used by the current
read-only Reporter Gateway and root URL configuration. Any new absolute import
requires an explicit reviewed policy change. Local single-level relative
imports are allowed only inside `reporter_gateway`; parent-relative imports,
star imports, dynamic imports, `eval`, and `exec` are rejected.

The surface policy also parses, but never imports or renders, the current
development settings, root URL configuration, landing-page template, and CSS.
It fixes the inert installed-app/middleware profile, the single home route, a
closed passive HTML/attribute/directive subset, and CSS with no resource-loading
or legacy active-content constructs. Missing, dynamic, mutated, malformed,
unreadable, or out-of-root inputs fail closed with controlled reason codes.

The same policy locks the executable AST of the reporter view and response-
header middleware. A new endpoint, unsafe method, request-derived render
context, cookie, logging operation, relaxed cache/CSP/header behavior, or any
other executable change requires an explicit policy update. The files are
parsed but never imported or executed.

The lifecycle-migration policy parses the sole inert initial migration without
importing it. It fixes the empty dependency graph, exact model/field/type and
operation sequence, closed migration/model constructor calls, and absence of
additional numbered migrations. A separate Django drift test requires
`makemigrations --check --dry-run` to report no model changes.

The submission-migration policy likewise parses but never imports or executes
the sole `submission_workflow` migration. Its complete executable AST, empty
dependency graph, exact metadata-only fields, constraints, state/version shape,
timestamps, imports, and sole numbered-file set are fixed. Any schema, state,
constraint, data/SQL/custom-code, dynamic, import, or graph change requires an
explicit policy update, while malformed and out-of-root inputs fail closed.

The orchestration-source policy parses only `report_lifecycle/finalization.py`,
`report_lifecycle/deletion.py`, `report_lifecycle/retention.py`,
`report_lifecycle/cleanup.py`, `report_lifecycle/metadata_retention.py`, and
`report_lifecycle/audit_retention.py`. It fixes their exact imports, top-level members,
content-free immutable snapshot/plan fields, false capability flags, closed
call/raise allowlists, and executors whose only outcome is the reviewed
unavailable exception. Nested imports, database/network/crypto/I/O/logging/
scheduler calls, dynamic or mutating syntax, binding shadowing, and altered
executor bodies fail closed. Retention and cleanup alone may obtain server time
and normalize an aware timestamp to UTC through their exact allowlisted
`django.utils.timezone` calls.

The descriptor-source policy parses only
`security_interfaces/administrative_step_up_descriptors.py`. It fixes the
version-2 constants, imports, top-level members, immutable class profiles,
validator bodies, and closed call set. Added authentication, persistence,
network, file, logging, dynamic, or authorization behavior fails closed without
importing or executing the descriptor module.

The audit-descriptor source policy parses only
`security_interfaces/audit_descriptors.py` and compares its complete executable
AST with the reviewed inert audit-v1 profile. Registry, field, validator,
authorization-window, import, call, success-return, or side-effect changes fail
closed without importing, executing, or echoing the target source.

The alert-descriptor source policy applies the same non-executing exact-AST
boundary to `security_interfaces/alert_descriptors.py`. It makes every change to
the alert/severity/delivery registry, content-free fields, validators, false
durability/authorization results, imports, or effects an explicit review event.

The report step-up source policy locks the complete executable AST of
`security_interfaces/step_up_descriptors.py`. Identifier/counter fields,
algorithm and purpose registries, timing, unused state, validators, and every
false verification/authorization result remain inert unless explicitly reviewed.

The negative-capability policy parses only `security_interfaces/errors.py` and
`security_interfaces/unavailable.py`. It locks the controlled dependency/error
registry and every mandatory unavailable adapter to the exact executable AST
that raises the generic fail-closed error. Success returns, plaintext/development
fallbacks, added methods, logging, and other side effects require an explicit
reviewed policy change.

Passing these checks proves only source-level conformance for the exact files
that were scanned. It is not a complete HTML/CSS security parser, browser
behavior proof, PostgreSQL schema/durability proof, production migration
review, runtime sandbox, or semantic proof of a protected protocol. It does
not authorize a reporter form, persistence, protected service call,
authentication, recovery, upload, operator/admin route, or deployment
capability.
