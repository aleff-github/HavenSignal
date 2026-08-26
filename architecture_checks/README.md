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

Passing these checks proves only source-level conformance for the exact files
that were scanned. It is not a complete HTML/CSS security parser or browser
behavior proof and does not authorize a reporter form, persistence, protected
service call, authentication, recovery, upload, operator/admin route, or
deployment capability.
