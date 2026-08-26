# Architecture checks

This package contains static, non-executing checks for the current inert
dependency boundaries. It is not a runtime sandbox, credential boundary, or
substitute for process/network isolation.

The reporter policy is an exact allowlist of imports used by the current
read-only Reporter Gateway and root URL configuration. Any new absolute import
requires an explicit reviewed policy change. Local single-level relative
imports are allowed only inside `reporter_gateway`; parent-relative imports,
star imports, dynamic imports, `eval`, and `exec` are rejected.

Passing these checks proves only source-level conformance for the files that
were scanned. It does not authorize a reporter form, persistence, protected
service call, authentication, recovery, upload, operator/admin route, or
deployment capability.
