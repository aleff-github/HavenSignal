"""Negative tests for inert file-sandbox descriptors."""

from dataclasses import FrozenInstanceError, replace

from django.test import SimpleTestCase

from security_interfaces import (
    FILE_SANDBOX_CREDENTIAL_PROFILES_V1,
    FILE_SANDBOX_FILESYSTEM_PROFILES_V1,
    FILE_SANDBOX_JOB_LIFETIME_SECONDS,
    FILE_SANDBOX_MEMORY_MIB,
    FILE_SANDBOX_OPEN_FILE_DESCRIPTOR_MAX,
    FILE_SANDBOX_PARSE_RENDER_WALL_TIME_SECONDS,
    FILE_SANDBOX_PROCESS_THREAD_MAX,
    FILE_SANDBOX_PROTOCOL_VERSION,
    FILE_SANDBOX_REFERENCE_HYPERVISOR,
    FILE_SANDBOX_REFERENCE_HYPERVISOR_VERSION,
    FILE_SANDBOX_TRANSPORTS_V1,
    FILE_SANDBOX_VCPU_COUNT,
    FileSandboxComputeLimitProfileV1,
    FileSandboxCredentialProfile,
    FileSandboxDescriptorRejected,
    FileSandboxFilesystemProfile,
    FileSandboxIsolationProfileV1,
    FileSandboxTransport,
    expected_file_sandbox_protocol_profile_v1,
    validate_file_sandbox_protocol_profile_v1,
)


class FileSandboxProfileTests(SimpleTestCase):
    def test_constants_match_the_approved_sandbox_profile(self) -> None:
        self.assertEqual(FILE_SANDBOX_PROTOCOL_VERSION, 1)
        self.assertEqual(FILE_SANDBOX_REFERENCE_HYPERVISOR, "Firecracker")
        self.assertEqual(FILE_SANDBOX_REFERENCE_HYPERVISOR_VERSION, "1.16.1")
        self.assertEqual(FILE_SANDBOX_VCPU_COUNT, 1)
        self.assertEqual(FILE_SANDBOX_MEMORY_MIB, 768)
        self.assertEqual(FILE_SANDBOX_PROCESS_THREAD_MAX, 32)
        self.assertEqual(FILE_SANDBOX_OPEN_FILE_DESCRIPTOR_MAX, 128)
        self.assertEqual(FILE_SANDBOX_PARSE_RENDER_WALL_TIME_SECONDS, 60)
        self.assertEqual(FILE_SANDBOX_JOB_LIFETIME_SECONDS, 120)
        self.assertEqual(
            FILE_SANDBOX_TRANSPORTS_V1,
            (FileSandboxTransport.AUTHENTICATED_VSOCK,),
        )
        self.assertEqual(
            FILE_SANDBOX_FILESYSTEM_PROFILES_V1,
            (
                FileSandboxFilesystemProfile.READ_ONLY_MEASURED_ROOT,
                FileSandboxFilesystemProfile.GUEST_RAM_TMPFS_ONLY,
                FileSandboxFilesystemProfile.ZERO_REUSABLE_WORKSPACE,
            ),
        )
        self.assertEqual(
            FILE_SANDBOX_CREDENTIAL_PROFILES_V1,
            (
                FileSandboxCredentialProfile.ONE_TIME_JOB_CAPABILITY,
                FileSandboxCredentialProfile.NO_PRODUCTION_CREDENTIALS,
            ),
        )

    def test_validated_profile_is_inert_and_non_authorizing(self) -> None:
        validated = validate_file_sandbox_protocol_profile_v1(
            expected_file_sandbox_protocol_profile_v1()
        )
        self.assertFalse(validated.boots_microvm)
        self.assertFalse(validated.executes_parser)
        self.assertFalse(validated.opens_files)
        self.assertFalse(validated.creates_job)
        self.assertFalse(validated.exchanges_vsock_messages)
        self.assertFalse(validated.inspects_attachment_bytes)
        self.assertFalse(validated.persists_plaintext)
        self.assertFalse(validated.authorizes_file_processing)
        self.assertTrue(validated.profile.isolation_profile.fresh_microvm_per_job)
        self.assertFalse(validated.profile.isolation_profile.virtual_nic_allowed)
        self.assertFalse(validated.profile.isolation_profile.dns_allowed)
        self.assertFalse(validated.profile.isolation_profile.snapshots_allowed)
        self.assertFalse(
            validated
            .profile
            .storage_credential_profile
            .reusable_storage_credentials_allowed
        )
        for field_name in (
            "job_id",
            "object_id",
            "file_bytes",
            "stdout",
            "stderr",
            "host_path",
            "vsock_socket",
        ):
            with self.subTest(field_name=field_name):
                self.assertFalse(hasattr(validated, field_name))


class FileSandboxValidationTests(SimpleTestCase):
    def test_profile_rejects_changed_compute_limits(self) -> None:
        valid = expected_file_sandbox_protocol_profile_v1()
        for candidate in (
            object(),
            replace(valid, scheme_version=2),
            replace(
                valid,
                compute_limits=FileSandboxComputeLimitProfileV1(
                    vcpu_count=2,
                    memory_mib=FILE_SANDBOX_MEMORY_MIB,
                    process_thread_max=FILE_SANDBOX_PROCESS_THREAD_MAX,
                    open_file_descriptor_max=FILE_SANDBOX_OPEN_FILE_DESCRIPTOR_MAX,
                    parse_render_wall_time_seconds=(
                        FILE_SANDBOX_PARSE_RENDER_WALL_TIME_SECONDS
                    ),
                    job_lifetime_seconds=FILE_SANDBOX_JOB_LIFETIME_SECONDS,
                ),
            ),
            replace(
                valid,
                compute_limits=replace(
                    valid.compute_limits,
                    job_lifetime_seconds=FILE_SANDBOX_JOB_LIFETIME_SECONDS + 1,
                ),
            ),
        ):
            with self.subTest(candidate=candidate):
                with self.assertRaises(FileSandboxDescriptorRejected):
                    validate_file_sandbox_protocol_profile_v1(candidate)

    def test_profile_rejects_weakened_isolation_transport_and_storage(self) -> None:
        valid = expected_file_sandbox_protocol_profile_v1()
        for candidate in (
            replace(
                valid,
                isolation_profile=FileSandboxIsolationProfileV1(
                    hypervisor=FILE_SANDBOX_REFERENCE_HYPERVISOR,
                    reference_hypervisor_version=(
                        FILE_SANDBOX_REFERENCE_HYPERVISOR_VERSION
                    ),
                    fresh_microvm_per_job=False,
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
            ),
            replace(
                valid,
                isolation_profile=replace(
                    valid.isolation_profile,
                    virtual_nic_allowed=True,
                ),
            ),
            replace(
                valid,
                transport_profile=replace(
                    valid.transport_profile,
                    transports=("HTTP",),
                ),
            ),
            replace(
                valid,
                storage_credential_profile=replace(
                    valid.storage_credential_profile,
                    durable_workspace_reuse_allowed=True,
                ),
            ),
        ):
            with self.subTest(candidate=candidate):
                with self.assertRaises(FileSandboxDescriptorRejected):
                    validate_file_sandbox_protocol_profile_v1(candidate)

    def test_descriptors_are_immutable(self) -> None:
        profile = expected_file_sandbox_protocol_profile_v1()
        with self.assertRaises(FrozenInstanceError):
            profile.scheme_version = 2

        validated = validate_file_sandbox_protocol_profile_v1(profile)
        with self.assertRaises((FrozenInstanceError, TypeError)):
            validated.boots_microvm = True

    def test_controlled_error_never_echoes_source_value(self) -> None:
        sentinel = "FILE_SANDBOX_SENTINEL"
        valid = expected_file_sandbox_protocol_profile_v1()
        with self.assertRaises(FileSandboxDescriptorRejected) as raised:
            validate_file_sandbox_protocol_profile_v1(
                replace(valid, isolation_profile=sentinel)
            )
        self.assertEqual(
            str(raised.exception),
            "file_sandbox_descriptor_rejected",
        )
        self.assertNotIn(sentinel, repr(raised.exception))
        self.assertIsNone(raised.exception.__cause__)
        self.assertIsNone(raised.exception.__context__)
