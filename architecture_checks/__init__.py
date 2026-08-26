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
from .surfaces import (
    EXPECTED_SETTINGS,
    SurfaceViolation,
    SurfaceViolationCode,
    analyze_css_source,
    analyze_settings_source,
    analyze_template_source,
    analyze_urlconf_source,
    scan_surface_file,
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
    "EXPECTED_SETTINGS",
    "SurfaceViolation",
    "SurfaceViolationCode",
    "analyze_css_source",
    "analyze_settings_source",
    "analyze_template_source",
    "analyze_urlconf_source",
    "scan_surface_file",
]
