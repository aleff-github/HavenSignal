"""Inert file-sandbox isolation descriptors for the approved v1 profile.

This module validates only static sandbox-boundary metadata. It does not boot
microVMs, run parsers, open files, create jobs, exchange vsock messages, inspect
attachments, persist data, log request material, or authorize file processing.
"""

from dataclasses import dataclass
from enum import StrEnum
from typing import Never

from .errors import FileSandboxDescriptorRejected


FILE_SANDBOX_PROTOCOL_VERSION = 1
FILE_SANDBOX_REFERENCE_HYPERVISOR = "Firecracker"
FILE_SANDBOX_REFERENCE_HYPERVISOR_VERSION = "1.16.1"
FILE_SANDBOX_VCPU_COUNT = 1
FILE_SANDBOX_MEMORY_MIB = 768
FILE_SANDBOX_PROCESS_THREAD_MAX = 32
FILE_SANDBOX_OPEN_FILE_DESCRIPTOR_MAX = 128
FILE_SANDBOX_PARSE_RENDER_WALL_TIME_SECONDS = 60
FILE_SANDBOX_JOB_LIFETIME_SECONDS = 120


class FileSandboxTransport(StrEnum):
    AUTHENTICATED_VSOCK = "AUTHENTICATED_VSOCK"


class FileSandboxFilesystemProfile(StrEnum):
    READ_ONLY_MEASURED_ROOT = "READ_ONLY_MEASURED_ROOT"
    GUEST_RAM_TMPFS_ONLY = "GUEST_RAM_TMPFS_ONLY"
    ZERO_REUSABLE_WORKSPACE = "ZERO_REUSABLE_WORKSPACE"


class FileSandboxCredentialProfile(StrEnum):
    ONE_TIME_JOB_CAPABILITY = "ONE_TIME_JOB_CAPABILITY"
    NO_PRODUCTION_CREDENTIALS = "NO_PRODUCTION_CREDENTIALS"


FILE_SANDBOX_TRANSPORTS_V1 = (FileSandboxTransport.AUTHENTICATED_VSOCK,)
FILE_SANDBOX_FILESYSTEM_PROFILES_V1 = (
    FileSandboxFilesystemProfile.READ_ONLY_MEASURED_ROOT,
    FileSandboxFilesystemProfile.GUEST_RAM_TMPFS_ONLY,
    FileSandboxFilesystemProfile.ZERO_REUSABLE_WORKSPACE,
)
FILE_SANDBOX_CREDENTIAL_PROFILES_V1 = (
    FileSandboxCredentialProfile.ONE_TIME_JOB_CAPABILITY,
    FileSandboxCredentialProfile.NO_PRODUCTION_CREDENTIALS,
)


@dataclass(frozen=True, slots=True)
class FileSandboxComputeLimitProfileV1:
    vcpu_count: int
    memory_mib: int
    process_thread_max: int
    open_file_descriptor_max: int
    parse_render_wall_time_seconds: int
    job_lifetime_seconds: int


@dataclass(frozen=True, slots=True)
class FileSandboxIsolationProfileV1:
    hypervisor: str
    reference_hypervisor_version: str
    fresh_microvm_per_job: bool
    docker_container_only_allowed: bool
    normal_process_allowed: bool
    virtual_nic_allowed: bool
    mmds_allowed: bool
    dns_allowed: bool
    host_network_namespace_allowed: bool
    package_manager_allowed: bool
    shell_allowed: bool
    ssh_allowed: bool
    ptrace_allowed: bool
    swap_allowed: bool
    snapshots_allowed: bool
    core_dumps_allowed: bool


@dataclass(frozen=True, slots=True)
class FileSandboxTransportProfileV1:
    transports: tuple[FileSandboxTransport, ...]
    exact_job_identity_required: bool
    exact_object_identity_required: bool
    monotonic_sequence_required: bool
    output_ceiling_required: bool


@dataclass(frozen=True, slots=True)
class FileSandboxStorageCredentialProfileV1:
    filesystem_profiles: tuple[FileSandboxFilesystemProfile, ...]
    credential_profiles: tuple[FileSandboxCredentialProfile, ...]
    writable_shared_host_filesystem_allowed: bool
    reusable_storage_credentials_allowed: bool
    durable_workspace_reuse_allowed: bool


@dataclass(frozen=True, slots=True)
class FileSandboxProtocolProfileV1:
    scheme_version: int
    compute_limits: FileSandboxComputeLimitProfileV1
    isolation_profile: FileSandboxIsolationProfileV1
    transport_profile: FileSandboxTransportProfileV1
    storage_credential_profile: FileSandboxStorageCredentialProfileV1


@dataclass(frozen=True, slots=True)
class StructurallyValidFileSandboxProfileV1:
    profile: FileSandboxProtocolProfileV1

    @property
    def boots_microvm(self) -> bool:
        return False

    @property
    def executes_parser(self) -> bool:
        return False

    @property
    def opens_files(self) -> bool:
        return False

    @property
    def creates_job(self) -> bool:
        return False

    @property
    def exchanges_vsock_messages(self) -> bool:
        return False

    @property
    def inspects_attachment_bytes(self) -> bool:
        return False

    @property
    def persists_plaintext(self) -> bool:
        return False

    @property
    def authorizes_file_processing(self) -> bool:
        return False


def _reject() -> Never:
    raise FileSandboxDescriptorRejected()


def _require_uint_exact(value: object, *, expected: int) -> int:
    if type(value) is not int or value != expected:
        _reject()
    return value


def _require_bool_exact(value: object, *, expected: bool) -> bool:
    if type(value) is not bool or value is not expected:
        _reject()
    return value


def _require_string_exact(value: object, *, expected: str) -> str:
    if type(value) is not str or value != expected:
        _reject()
    return value


def _require_transport(value: object) -> FileSandboxTransport:
    if isinstance(value, FileSandboxTransport):
        return value
    if type(value) is str:
        for transport in FileSandboxTransport:
            if value == transport.value:
                return transport
    _reject()


def _require_filesystem_profile(
    value: object,
) -> FileSandboxFilesystemProfile:
    if isinstance(value, FileSandboxFilesystemProfile):
        return value
    if type(value) is str:
        for filesystem_profile in FileSandboxFilesystemProfile:
            if value == filesystem_profile.value:
                return filesystem_profile
    _reject()


def _require_credential_profile(
    value: object,
) -> FileSandboxCredentialProfile:
    if isinstance(value, FileSandboxCredentialProfile):
        return value
    if type(value) is str:
        for credential_profile in FileSandboxCredentialProfile:
            if value == credential_profile.value:
                return credential_profile
    _reject()


def _require_transports(
    value: object,
) -> tuple[FileSandboxTransport, ...]:
    if type(value) is not tuple:
        _reject()
    normalized = tuple(_require_transport(transport) for transport in value)
    if normalized != FILE_SANDBOX_TRANSPORTS_V1:
        _reject()
    return normalized


def _require_filesystem_profiles(
    value: object,
) -> tuple[FileSandboxFilesystemProfile, ...]:
    if type(value) is not tuple:
        _reject()
    normalized = tuple(
        _require_filesystem_profile(filesystem_profile)
        for filesystem_profile in value
    )
    if normalized != FILE_SANDBOX_FILESYSTEM_PROFILES_V1:
        _reject()
    return normalized


def _require_credential_profiles(
    value: object,
) -> tuple[FileSandboxCredentialProfile, ...]:
    if type(value) is not tuple:
        _reject()
    normalized = tuple(
        _require_credential_profile(credential_profile)
        for credential_profile in value
    )
    if normalized != FILE_SANDBOX_CREDENTIAL_PROFILES_V1:
        _reject()
    return normalized


def validate_file_sandbox_compute_limit_profile_v1(
    profile: FileSandboxComputeLimitProfileV1,
) -> FileSandboxComputeLimitProfileV1:
    if type(profile) is not FileSandboxComputeLimitProfileV1:
        _reject()
    return FileSandboxComputeLimitProfileV1(
        vcpu_count=_require_uint_exact(
            profile.vcpu_count,
            expected=FILE_SANDBOX_VCPU_COUNT,
        ),
        memory_mib=_require_uint_exact(
            profile.memory_mib,
            expected=FILE_SANDBOX_MEMORY_MIB,
        ),
        process_thread_max=_require_uint_exact(
            profile.process_thread_max,
            expected=FILE_SANDBOX_PROCESS_THREAD_MAX,
        ),
        open_file_descriptor_max=_require_uint_exact(
            profile.open_file_descriptor_max,
            expected=FILE_SANDBOX_OPEN_FILE_DESCRIPTOR_MAX,
        ),
        parse_render_wall_time_seconds=_require_uint_exact(
            profile.parse_render_wall_time_seconds,
            expected=FILE_SANDBOX_PARSE_RENDER_WALL_TIME_SECONDS,
        ),
        job_lifetime_seconds=_require_uint_exact(
            profile.job_lifetime_seconds,
            expected=FILE_SANDBOX_JOB_LIFETIME_SECONDS,
        ),
    )


def validate_file_sandbox_isolation_profile_v1(
    profile: FileSandboxIsolationProfileV1,
) -> FileSandboxIsolationProfileV1:
    if type(profile) is not FileSandboxIsolationProfileV1:
        _reject()
    return FileSandboxIsolationProfileV1(
        hypervisor=_require_string_exact(
            profile.hypervisor,
            expected=FILE_SANDBOX_REFERENCE_HYPERVISOR,
        ),
        reference_hypervisor_version=_require_string_exact(
            profile.reference_hypervisor_version,
            expected=FILE_SANDBOX_REFERENCE_HYPERVISOR_VERSION,
        ),
        fresh_microvm_per_job=_require_bool_exact(
            profile.fresh_microvm_per_job,
            expected=True,
        ),
        docker_container_only_allowed=_require_bool_exact(
            profile.docker_container_only_allowed,
            expected=False,
        ),
        normal_process_allowed=_require_bool_exact(
            profile.normal_process_allowed,
            expected=False,
        ),
        virtual_nic_allowed=_require_bool_exact(
            profile.virtual_nic_allowed,
            expected=False,
        ),
        mmds_allowed=_require_bool_exact(profile.mmds_allowed, expected=False),
        dns_allowed=_require_bool_exact(profile.dns_allowed, expected=False),
        host_network_namespace_allowed=_require_bool_exact(
            profile.host_network_namespace_allowed,
            expected=False,
        ),
        package_manager_allowed=_require_bool_exact(
            profile.package_manager_allowed,
            expected=False,
        ),
        shell_allowed=_require_bool_exact(
            profile.shell_allowed,
            expected=False,
        ),
        ssh_allowed=_require_bool_exact(profile.ssh_allowed, expected=False),
        ptrace_allowed=_require_bool_exact(
            profile.ptrace_allowed,
            expected=False,
        ),
        swap_allowed=_require_bool_exact(profile.swap_allowed, expected=False),
        snapshots_allowed=_require_bool_exact(
            profile.snapshots_allowed,
            expected=False,
        ),
        core_dumps_allowed=_require_bool_exact(
            profile.core_dumps_allowed,
            expected=False,
        ),
    )


def validate_file_sandbox_transport_profile_v1(
    profile: FileSandboxTransportProfileV1,
) -> FileSandboxTransportProfileV1:
    if type(profile) is not FileSandboxTransportProfileV1:
        _reject()
    return FileSandboxTransportProfileV1(
        transports=_require_transports(profile.transports),
        exact_job_identity_required=_require_bool_exact(
            profile.exact_job_identity_required,
            expected=True,
        ),
        exact_object_identity_required=_require_bool_exact(
            profile.exact_object_identity_required,
            expected=True,
        ),
        monotonic_sequence_required=_require_bool_exact(
            profile.monotonic_sequence_required,
            expected=True,
        ),
        output_ceiling_required=_require_bool_exact(
            profile.output_ceiling_required,
            expected=True,
        ),
    )


def validate_file_sandbox_storage_credential_profile_v1(
    profile: FileSandboxStorageCredentialProfileV1,
) -> FileSandboxStorageCredentialProfileV1:
    if type(profile) is not FileSandboxStorageCredentialProfileV1:
        _reject()
    return FileSandboxStorageCredentialProfileV1(
        filesystem_profiles=_require_filesystem_profiles(
            profile.filesystem_profiles
        ),
        credential_profiles=_require_credential_profiles(
            profile.credential_profiles
        ),
        writable_shared_host_filesystem_allowed=_require_bool_exact(
            profile.writable_shared_host_filesystem_allowed,
            expected=False,
        ),
        reusable_storage_credentials_allowed=_require_bool_exact(
            profile.reusable_storage_credentials_allowed,
            expected=False,
        ),
        durable_workspace_reuse_allowed=_require_bool_exact(
            profile.durable_workspace_reuse_allowed,
            expected=False,
        ),
    )


def validate_file_sandbox_protocol_profile_v1(
    profile: FileSandboxProtocolProfileV1,
) -> StructurallyValidFileSandboxProfileV1:
    if type(profile) is not FileSandboxProtocolProfileV1:
        _reject()
    normalized = FileSandboxProtocolProfileV1(
        scheme_version=_require_uint_exact(
            profile.scheme_version,
            expected=FILE_SANDBOX_PROTOCOL_VERSION,
        ),
        compute_limits=validate_file_sandbox_compute_limit_profile_v1(
            profile.compute_limits
        ),
        isolation_profile=validate_file_sandbox_isolation_profile_v1(
            profile.isolation_profile
        ),
        transport_profile=validate_file_sandbox_transport_profile_v1(
            profile.transport_profile
        ),
        storage_credential_profile=(
            validate_file_sandbox_storage_credential_profile_v1(
                profile.storage_credential_profile
            )
        ),
    )
    return StructurallyValidFileSandboxProfileV1(profile=normalized)


def expected_file_sandbox_protocol_profile_v1() -> FileSandboxProtocolProfileV1:
    """Return only the approved sandbox-boundary metadata."""

    return FileSandboxProtocolProfileV1(
        scheme_version=FILE_SANDBOX_PROTOCOL_VERSION,
        compute_limits=FileSandboxComputeLimitProfileV1(
            vcpu_count=FILE_SANDBOX_VCPU_COUNT,
            memory_mib=FILE_SANDBOX_MEMORY_MIB,
            process_thread_max=FILE_SANDBOX_PROCESS_THREAD_MAX,
            open_file_descriptor_max=FILE_SANDBOX_OPEN_FILE_DESCRIPTOR_MAX,
            parse_render_wall_time_seconds=(
                FILE_SANDBOX_PARSE_RENDER_WALL_TIME_SECONDS
            ),
            job_lifetime_seconds=FILE_SANDBOX_JOB_LIFETIME_SECONDS,
        ),
        isolation_profile=FileSandboxIsolationProfileV1(
            hypervisor=FILE_SANDBOX_REFERENCE_HYPERVISOR,
            reference_hypervisor_version=(
                FILE_SANDBOX_REFERENCE_HYPERVISOR_VERSION
            ),
            fresh_microvm_per_job=True,
            docker_container_only_allowed=False,
            normal_process_allowed=False,
            virtual_nic_allowed=False,
            mmds_allowed=False,
            dns_allowed=False,
            host_network_namespace_allowed=False,
            package_manager_allowed=False,
            shell_allowed=False,
            ssh_allowed=False,
            ptrace_allowed=False,
            swap_allowed=False,
            snapshots_allowed=False,
            core_dumps_allowed=False,
        ),
        transport_profile=FileSandboxTransportProfileV1(
            transports=FILE_SANDBOX_TRANSPORTS_V1,
            exact_job_identity_required=True,
            exact_object_identity_required=True,
            monotonic_sequence_required=True,
            output_ceiling_required=True,
        ),
        storage_credential_profile=FileSandboxStorageCredentialProfileV1(
            filesystem_profiles=FILE_SANDBOX_FILESYSTEM_PROFILES_V1,
            credential_profiles=FILE_SANDBOX_CREDENTIAL_PROFILES_V1,
            writable_shared_host_filesystem_allowed=False,
            reusable_storage_credentials_allowed=False,
            durable_workspace_reuse_allowed=False,
        ),
    )
