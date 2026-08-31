"""Non-executing source policy for inert security descriptors."""

import ast
import hashlib
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from types import MappingProxyType


class DescriptorViolationCode(StrEnum):
    CALL_PROFILE_MISMATCH = "CALL_PROFILE_MISMATCH"
    CLASS_PROFILE_MISMATCH = "CLASS_PROFILE_MISMATCH"
    CONSTANT_PROFILE_MISMATCH = "CONSTANT_PROFILE_MISMATCH"
    DYNAMIC_CONSTRUCT = "DYNAMIC_CONSTRUCT"
    FUNCTION_PROFILE_MISMATCH = "FUNCTION_PROFILE_MISMATCH"
    IMPORT_PROFILE_MISMATCH = "IMPORT_PROFILE_MISMATCH"
    MODULE_PROFILE_MISMATCH = "MODULE_PROFILE_MISMATCH"
    SOURCE_PARSE_ERROR = "SOURCE_PARSE_ERROR"
    TARGET_SET_MISMATCH = "TARGET_SET_MISMATCH"


@dataclass(frozen=True, slots=True)
class DescriptorSourceViolation:
    code: DescriptorViolationCode
    relative_path: str
    line: int
    detail_code: str


ADMINISTRATIVE_STEP_UP_DESCRIPTOR_PATH = (
    "security_interfaces/administrative_step_up_descriptors.py"
)
AUDIT_DESCRIPTOR_PATH = "security_interfaces/audit_descriptors.py"
EXPECTED_AUDIT_DESCRIPTOR_AST_DIGEST = (
    "b89cd3f916c4834e8041d2cb622bb60d59f1ee892a8ea0e88688245cb8a3eb46"
)
ALERT_DESCRIPTOR_PATH = "security_interfaces/alert_descriptors.py"
EXPECTED_ALERT_DESCRIPTOR_AST_DIGEST = (
    "9a5767aad3a68ac40ce6c957d4880e554163f809aef7d2c32476a04b8aa0c972"
)

_EXPECTED_IMPORTS = (
    (0, "dataclasses", (("dataclass", None),)),
    (0, "datetime", (("datetime", None), ("timedelta", None))),
    (0, "typing", (("Never", None),)),
    (1, "audit_descriptors", (("MAX_CBOR_UINT", None),)),
    (1, "errors", (("StepUpDescriptorRejected", None),)),
    (
        1,
        "step_up_descriptors",
        (("StepUpArtifactBindingPurpose", None),),
    ),
)

_EXPECTED_MEMBERS = (
    ("assign", "ADMINISTRATIVE_STEP_UP_PROTOCOL_VERSION"),
    ("assign", "ADMINISTRATIVE_STEP_UP_TTL_MS"),
    ("class", "AdministrativeStepUpIdentityV2"),
    ("class", "AdministrativeStepUpArtifactProfileV2"),
    ("class", "AdministrativeStepUpTimingV2"),
    ("class", "AdministrativeStepUpUnusedStateV2"),
    ("class", "StructurallyValidAdministrativeStepUpFoundationsV2"),
    ("function", "_reject"),
    ("function", "_require_exact_bytes"),
    ("function", "_require_uint"),
    ("function", "_require_binding_purpose"),
    ("function", "validate_administrative_step_up_identity_v2"),
    (
        "function",
        "validate_administrative_step_up_artifact_profile_v2",
    ),
    ("function", "validate_administrative_step_up_timing_v2"),
    ("function", "validate_administrative_step_up_unused_state_v2"),
    ("function", "validate_administrative_step_up_foundations_v2"),
)

_EXPECTED_CLASS_DIGESTS = MappingProxyType(
    {
        "AdministrativeStepUpIdentityV2": (
            "00db2987127f3ec9ceaf011cbb744719213f818307946b059ae84f45cb481cf5"
        ),
        "AdministrativeStepUpArtifactProfileV2": (
            "42853c92822bab1dfd2d2300ed6e53557f0e6bb19126c4ebadb970534e2c4f4e"
        ),
        "AdministrativeStepUpTimingV2": (
            "3becdf90559642ab15ad0f58e3a918aa472a805a4f386dcc9e9a629e5ca6d899"
        ),
        "AdministrativeStepUpUnusedStateV2": (
            "063aa1ba09a643c6f5b7f3b127874ec84be48ec1b900310aa5339083c951fb5f"
        ),
        "StructurallyValidAdministrativeStepUpFoundationsV2": (
            "705e79620919e425e6512ed15cc0edefeafd19253dd035ad709eac4a771bc224"
        ),
    }
)

_EXPECTED_FUNCTION_DIGESTS = MappingProxyType(
    {
        "_reject": (
            "06e39580620cdbf3f6be9d102bb05a20c4eca107dd8c447d229ad72c0d1e4926"
        ),
        "_require_exact_bytes": (
            "91686cf1b103ac1ecce258b013f0933616291a8588c91d388b700f2f47df48a9"
        ),
        "_require_uint": (
            "39ba97ca4cc129d93a1a1ceb2977fc2ee2903b6e794d12157d710a1157e7c7bd"
        ),
        "_require_binding_purpose": (
            "c2211cb272716ca87e943c7b34c92361516a30e4dcd3b8916f55bc9d0c7c511f"
        ),
        "validate_administrative_step_up_identity_v2": (
            "53e6bd4338a726ce5eb270a5c97bd603de7249125d258c5cf6ea7c38a21a05c9"
        ),
        "validate_administrative_step_up_artifact_profile_v2": (
            "17f73581e5840616f1b9466355a067e763926869f22b486f627bf0aa26958d26"
        ),
        "validate_administrative_step_up_timing_v2": (
            "c751f6f30e56effe517687a673c5a9b4b7f3c494ec9c22915e8b8274d410d2e7"
        ),
        "validate_administrative_step_up_unused_state_v2": (
            "29003a7a64354006ea43db25964fb2ede6730f26db091c6f5eee17b235406caf"
        ),
        "validate_administrative_step_up_foundations_v2": (
            "cc3bdba14088063dc5a7774448ff64dd8251116fb52b8ae8679fa77dc758ca62"
        ),
    }
)

_ALLOWED_CALLS = frozenset(
    {
        "AdministrativeStepUpArtifactProfileV2",
        "AdministrativeStepUpIdentityV2",
        "AdministrativeStepUpTimingV2",
        "AdministrativeStepUpUnusedStateV2",
        "StepUpDescriptorRejected",
        "StructurallyValidAdministrativeStepUpFoundationsV2",
        "_reject",
        "_require_binding_purpose",
        "_require_exact_bytes",
        "_require_uint",
        "dataclass",
        "isinstance",
        "len",
        "timedelta",
        "timing.expires_at.utcoffset",
        "timing.issued_at.utcoffset",
        "type",
        "validate_administrative_step_up_artifact_profile_v2",
        "validate_administrative_step_up_identity_v2",
        "validate_administrative_step_up_timing_v2",
        "validate_administrative_step_up_unused_state_v2",
    }
)

_DYNAMIC_NODES = (
    ast.AsyncFunctionDef,
    ast.Await,
    ast.Delete,
    ast.Global,
    ast.Lambda,
    ast.Nonlocal,
    ast.Yield,
    ast.YieldFrom,
)


def _violation(
    code: DescriptorViolationCode,
    relative_path: str,
    line: int,
    detail_code: str,
) -> DescriptorSourceViolation:
    return DescriptorSourceViolation(code, relative_path, line, detail_code)


def _sorted(
    violations: list[DescriptorSourceViolation],
) -> tuple[DescriptorSourceViolation, ...]:
    return tuple(
        sorted(
            violations,
            key=lambda item: (
                item.relative_path,
                item.line,
                item.code.value,
                item.detail_code,
            ),
        )
    )


def _import_identity(node: ast.ImportFrom) -> tuple[
    int, str | None, tuple[tuple[str, str | None], ...]
]:
    return (
        node.level,
        node.module,
        tuple((alias.name, alias.asname) for alias in node.names),
    )


def _assignment_name(node: ast.Assign) -> str | None:
    if len(node.targets) != 1 or not isinstance(node.targets[0], ast.Name):
        return None
    return node.targets[0].id


def _call_name(node: ast.Call) -> str | None:
    parts: list[str] = []
    current: ast.AST = node.func
    while isinstance(current, ast.Attribute):
        parts.append(current.attr)
        current = current.value
    if not isinstance(current, ast.Name):
        return None
    parts.append(current.id)
    return ".".join(reversed(parts))


def _node_digest(node: ast.AST) -> str:
    payload = ast.dump(
        node,
        annotate_fields=True,
        include_attributes=False,
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _constant_profile_matches(assignments: dict[str, ast.Assign]) -> bool:
    version = assignments.get("ADMINISTRATIVE_STEP_UP_PROTOCOL_VERSION")
    ttl = assignments.get("ADMINISTRATIVE_STEP_UP_TTL_MS")
    if version is None or ttl is None:
        return False
    valid_version = (
        isinstance(version.value, ast.Constant)
        and type(version.value.value) is int
        and version.value.value == 2
    )
    valid_ttl = (
        isinstance(ttl.value, ast.BinOp)
        and isinstance(ttl.value.op, ast.Mult)
        and isinstance(ttl.value.left, ast.Constant)
        and type(ttl.value.left.value) is int
        and ttl.value.left.value == 120
        and isinstance(ttl.value.right, ast.Constant)
        and type(ttl.value.right.value) is int
        and ttl.value.right.value == 1000
    )
    return valid_version and valid_ttl


def analyze_administrative_step_up_descriptor_source(
    *, source: str, relative_path: str = ADMINISTRATIVE_STEP_UP_DESCRIPTOR_PATH
) -> tuple[DescriptorSourceViolation, ...]:
    """Check the exact inert v2 foundations without importing the source."""

    if relative_path != ADMINISTRATIVE_STEP_UP_DESCRIPTOR_PATH:
        return (
            _violation(
                DescriptorViolationCode.TARGET_SET_MISMATCH,
                relative_path,
                0,
                "ADMINISTRATIVE_STEP_UP_TARGET",
            ),
        )
    try:
        tree = ast.parse(source, filename=relative_path)
    except (SyntaxError, ValueError, TypeError, MemoryError, RecursionError):
        return (
            _violation(
                DescriptorViolationCode.SOURCE_PARSE_ERROR,
                relative_path,
                0,
                "PYTHON_SOURCE_INVALID",
            ),
        )

    violations: list[DescriptorSourceViolation] = []
    imports = tuple(
        _import_identity(node)
        for node in tree.body
        if isinstance(node, ast.ImportFrom)
    )
    other_imports = [
        node
        for node in ast.walk(tree)
        if isinstance(node, (ast.Import, ast.ImportFrom))
        and node not in tree.body
    ]
    direct_imports = [node for node in tree.body if isinstance(node, ast.Import)]
    if imports != _EXPECTED_IMPORTS or direct_imports or other_imports:
        violations.append(
            _violation(
                DescriptorViolationCode.IMPORT_PROFILE_MISMATCH,
                relative_path,
                0,
                "EXACT_IMPORT_SET",
            )
        )

    members: list[tuple[str, str]] = []
    assignments: dict[str, ast.Assign] = {}
    classes: dict[str, ast.ClassDef] = {}
    functions: dict[str, ast.FunctionDef] = {}
    invalid_top_level: list[ast.AST] = []
    for index, node in enumerate(tree.body):
        if index == 0 and isinstance(node, ast.Expr) and isinstance(
            node.value, ast.Constant
        ) and type(node.value.value) is str:
            continue
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            continue
        if isinstance(node, ast.Assign):
            name = _assignment_name(node)
            if name is None:
                invalid_top_level.append(node)
            else:
                assignments[name] = node
                members.append(("assign", name))
        elif isinstance(node, ast.ClassDef):
            classes[node.name] = node
            members.append(("class", node.name))
        elif isinstance(node, ast.FunctionDef):
            functions[node.name] = node
            members.append(("function", node.name))
        else:
            invalid_top_level.append(node)
    if tuple(members) != _EXPECTED_MEMBERS or invalid_top_level:
        violations.append(
            _violation(
                DescriptorViolationCode.MODULE_PROFILE_MISMATCH,
                relative_path,
                0,
                "EXACT_MODULE_MEMBERS",
            )
        )

    if not _constant_profile_matches(assignments):
        violations.append(
            _violation(
                DescriptorViolationCode.CONSTANT_PROFILE_MISMATCH,
                relative_path,
                0,
                "VERSION_AND_TTL",
            )
        )

    class_digests = {name: _node_digest(node) for name, node in classes.items()}
    if class_digests != dict(_EXPECTED_CLASS_DIGESTS):
        violations.append(
            _violation(
                DescriptorViolationCode.CLASS_PROFILE_MISMATCH,
                relative_path,
                0,
                "IMMUTABLE_CONTENT_FREE_CLASSES",
            )
        )

    function_digests = {
        name: _node_digest(node) for name, node in functions.items()
    }
    if function_digests != dict(_EXPECTED_FUNCTION_DIGESTS):
        violations.append(
            _violation(
                DescriptorViolationCode.FUNCTION_PROFILE_MISMATCH,
                relative_path,
                0,
                "EXACT_VALIDATORS",
            )
        )

    for node in ast.walk(tree):
        if isinstance(node, _DYNAMIC_NODES):
            violations.append(
                _violation(
                    DescriptorViolationCode.DYNAMIC_CONSTRUCT,
                    relative_path,
                    getattr(node, "lineno", 0),
                    type(node).__name__.upper(),
                )
            )
        elif isinstance(node, ast.Call):
            name = _call_name(node)
            if name not in _ALLOWED_CALLS:
                violations.append(
                    _violation(
                        DescriptorViolationCode.CALL_PROFILE_MISMATCH,
                        relative_path,
                        node.lineno,
                        "CALL_NOT_ALLOWLISTED",
                    )
                )
        elif isinstance(node, ast.Raise):
            name = _call_name(node.exc) if isinstance(node.exc, ast.Call) else None
            if name != "StepUpDescriptorRejected":
                violations.append(
                    _violation(
                        DescriptorViolationCode.CALL_PROFILE_MISMATCH,
                        relative_path,
                        node.lineno,
                        "RAISE_NOT_ALLOWLISTED",
                    )
                )
    return _sorted(violations)


def scan_administrative_step_up_descriptor_source(
    *, path: Path, relative_to: Path
) -> tuple[DescriptorSourceViolation, ...]:
    """Read the one reviewed target or fail closed with no source echo."""

    try:
        root = relative_to.resolve(strict=True)
        resolved = path.resolve(strict=True)
        relative_path = resolved.relative_to(root).as_posix()
        source = resolved.read_text(encoding="utf-8")
    except (OSError, UnicodeError, ValueError):
        return (
            _violation(
                DescriptorViolationCode.SOURCE_PARSE_ERROR,
                "<invalid-scan-path>",
                0,
                "TARGET_UNAVAILABLE",
            ),
        )
    return analyze_administrative_step_up_descriptor_source(
        source=source,
        relative_path=relative_path,
    )


def analyze_audit_descriptor_source(
    *, source: str, relative_path: str = AUDIT_DESCRIPTOR_PATH
) -> tuple[DescriptorSourceViolation, ...]:
    """Check the exact inert audit-v1 source without importing it."""

    if relative_path != AUDIT_DESCRIPTOR_PATH:
        return (
            _violation(
                DescriptorViolationCode.TARGET_SET_MISMATCH,
                relative_path,
                0,
                "AUDIT_DESCRIPTOR_TARGET",
            ),
        )
    try:
        tree = ast.parse(source, filename=relative_path)
    except (SyntaxError, ValueError, TypeError, MemoryError, RecursionError):
        return (
            _violation(
                DescriptorViolationCode.SOURCE_PARSE_ERROR,
                relative_path,
                0,
                "PYTHON_SOURCE_INVALID",
            ),
        )
    if _node_digest(tree) != EXPECTED_AUDIT_DESCRIPTOR_AST_DIGEST:
        return (
            _violation(
                DescriptorViolationCode.MODULE_PROFILE_MISMATCH,
                relative_path,
                0,
                "EXACT_INERT_AUDIT_DESCRIPTOR_AST",
            ),
        )
    return ()


def scan_audit_descriptor_source(
    *, path: Path, relative_to: Path
) -> tuple[DescriptorSourceViolation, ...]:
    """Read the reviewed audit target or fail closed without source echo."""

    try:
        root = relative_to.resolve(strict=True)
        resolved = path.resolve(strict=True)
        relative_path = resolved.relative_to(root).as_posix()
        source = resolved.read_text(encoding="utf-8")
    except (OSError, UnicodeError, ValueError):
        return (
            _violation(
                DescriptorViolationCode.SOURCE_PARSE_ERROR,
                "<invalid-scan-path>",
                0,
                "TARGET_UNAVAILABLE",
            ),
        )
    return analyze_audit_descriptor_source(
        source=source,
        relative_path=relative_path,
    )


def analyze_alert_descriptor_source(
    *, source: str, relative_path: str = ALERT_DESCRIPTOR_PATH
) -> tuple[DescriptorSourceViolation, ...]:
    """Check the exact inert alert-v1 source without importing it."""

    if relative_path != ALERT_DESCRIPTOR_PATH:
        return (
            _violation(
                DescriptorViolationCode.TARGET_SET_MISMATCH,
                relative_path,
                0,
                "ALERT_DESCRIPTOR_TARGET",
            ),
        )
    try:
        tree = ast.parse(source, filename=relative_path)
    except (SyntaxError, ValueError, TypeError, MemoryError, RecursionError):
        return (
            _violation(
                DescriptorViolationCode.SOURCE_PARSE_ERROR,
                relative_path,
                0,
                "PYTHON_SOURCE_INVALID",
            ),
        )
    if _node_digest(tree) != EXPECTED_ALERT_DESCRIPTOR_AST_DIGEST:
        return (
            _violation(
                DescriptorViolationCode.MODULE_PROFILE_MISMATCH,
                relative_path,
                0,
                "EXACT_INERT_ALERT_DESCRIPTOR_AST",
            ),
        )
    return ()


def scan_alert_descriptor_source(
    *, path: Path, relative_to: Path
) -> tuple[DescriptorSourceViolation, ...]:
    """Read the reviewed alert target or fail closed without source echo."""

    try:
        root = relative_to.resolve(strict=True)
        resolved = path.resolve(strict=True)
        relative_path = resolved.relative_to(root).as_posix()
        source = resolved.read_text(encoding="utf-8")
    except (OSError, UnicodeError, ValueError):
        return (
            _violation(
                DescriptorViolationCode.SOURCE_PARSE_ERROR,
                "<invalid-scan-path>",
                0,
                "TARGET_UNAVAILABLE",
            ),
        )
    return analyze_alert_descriptor_source(
        source=source,
        relative_path=relative_path,
    )
