"""Static architecture checks for deny-by-default dependency boundaries."""

from .imports import (
    REPORTER_GATEWAY_IMPORT_POLICY,
    REPORTER_ROOT_URL_IMPORT_POLICY,
    ArchitectureImportViolation,
    ImportPolicy,
    ImportViolationCode,
    analyze_python_source,
    scan_python_file,
    scan_python_package,
)

__all__ = [
    "REPORTER_GATEWAY_IMPORT_POLICY",
    "REPORTER_ROOT_URL_IMPORT_POLICY",
    "ArchitectureImportViolation",
    "ImportPolicy",
    "ImportViolationCode",
    "analyze_python_source",
    "scan_python_file",
    "scan_python_package",
]
