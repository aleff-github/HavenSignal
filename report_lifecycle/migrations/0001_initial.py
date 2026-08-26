import django.db.models.deletion
import uuid
from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='Report',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('state', models.CharField(choices=[('SEALED', 'Sealed'), ('CLAIMED', 'Claimed'), ('OPEN', 'Open'), ('INTERRUPTED', 'Interrupted'), ('FINALIZING', 'Finalizing'), ('RESPONSE_AVAILABLE', 'Response available'), ('DELETING', 'Deleting'), ('DELETING_FLOOD', 'Deleting during flood'), ('DESTROYED', 'Destroyed'), ('DELETED_WITH_REASON', 'Deleted with reason'), ('DELETED_UNOPENED_EMERGENCY', 'Deleted unopened during emergency')], default='SEALED', editable=False, max_length=32)),
                ('state_version', models.PositiveBigIntegerField(default=0, editable=False)),
                ('current_lease_generation', models.PositiveBigIntegerField(default=0, editable=False)),
                ('active_operator_id', models.UUIDField(editable=False, null=True)),
                ('received_at', models.DateTimeField(auto_now_add=True)),
                ('claimed_at', models.DateTimeField(editable=False, null=True)),
                ('claim_expires_at', models.DateTimeField(editable=False, null=True)),
                ('response_available_at', models.DateTimeField(editable=False, null=True)),
                ('terminal_at', models.DateTimeField(editable=False, null=True)),
            ],
            options={
                'db_table': 'report_lifecycle_report',
                'default_permissions': (),
                'indexes': [models.Index(fields=['state', 'received_at'], name='report_state_received_idx')],
                'constraints': [models.CheckConstraint(condition=models.Q(('state__in', ['SEALED', 'CLAIMED', 'OPEN', 'INTERRUPTED', 'FINALIZING', 'RESPONSE_AVAILABLE', 'DELETING', 'DELETING_FLOOD', 'DESTROYED', 'DELETED_WITH_REASON', 'DELETED_UNOPENED_EMERGENCY'])), name='report_known_state'), models.CheckConstraint(condition=models.Q(('state_version__gte', 0)), name='report_nonnegative_state_version'), models.CheckConstraint(condition=models.Q(('current_lease_generation__gte', 0)), name='report_nonnegative_lease_generation'), models.CheckConstraint(condition=models.Q(models.Q(('active_operator_id__isnull', False), ('state__in', ('CLAIMED', 'OPEN', 'FINALIZING', 'DELETING'))), models.Q(models.Q(('state__in', ('CLAIMED', 'OPEN', 'FINALIZING', 'DELETING')), _negated=True), ('active_operator_id__isnull', True)), _connector='OR'), name='report_operator_state_shape'), models.CheckConstraint(condition=models.Q(models.Q(('claim_expires_at__gt', models.F('claimed_at')), ('claim_expires_at__isnull', False), ('claimed_at__isnull', False), ('state', 'CLAIMED')), models.Q(models.Q(('state', 'CLAIMED'), _negated=True), ('claim_expires_at__isnull', True), ('claimed_at__isnull', True)), _connector='OR'), name='report_claim_timestamp_shape'), models.CheckConstraint(condition=models.Q(models.Q(('response_available_at__isnull', False), ('state__in', ('RESPONSE_AVAILABLE', 'DESTROYED'))), models.Q(models.Q(('state__in', ('RESPONSE_AVAILABLE', 'DESTROYED')), _negated=True), ('response_available_at__isnull', True)), _connector='OR'), name='report_response_timestamp_shape'), models.CheckConstraint(condition=models.Q(models.Q(('state__in', ('DESTROYED', 'DELETED_WITH_REASON', 'DELETED_UNOPENED_EMERGENCY')), ('terminal_at__isnull', False)), models.Q(models.Q(('state__in', ('DESTROYED', 'DELETED_WITH_REASON', 'DELETED_UNOPENED_EMERGENCY')), _negated=True), ('terminal_at__isnull', True)), _connector='OR'), name='report_terminal_timestamp_shape'), models.UniqueConstraint(condition=models.Q(('state__in', ('CLAIMED', 'OPEN', 'FINALIZING', 'DELETING'))), fields=('active_operator_id',), name='one_active_report_per_operator')],
            },
        ),
        migrations.CreateModel(
            name='ReportLease',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('operator_id', models.UUIDField(editable=False)),
                ('generation', models.PositiveBigIntegerField(editable=False)),
                ('state', models.CharField(choices=[('ACTIVE', 'Active'), ('RELEASED', 'Released'), ('EXPIRED', 'Expired'), ('INVALIDATED', 'Invalidated')], default='ACTIVE', editable=False, max_length=12)),
                ('state_version', models.PositiveBigIntegerField(default=0, editable=False)),
                ('opened_at', models.DateTimeField(editable=False)),
                ('last_activity_at', models.DateTimeField(editable=False)),
                ('absolute_expires_at', models.DateTimeField(editable=False)),
                ('closed_at', models.DateTimeField(editable=False, null=True)),
                ('report', models.ForeignKey(editable=False, on_delete=django.db.models.deletion.PROTECT, related_name='leases', to='report_lifecycle.report')),
            ],
            options={
                'db_table': 'report_lifecycle_lease',
                'default_permissions': (),
            },
        ),
        migrations.CreateModel(
            name='SecurityOperation',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('kind', models.CharField(choices=[('REOPEN_REPORT', 'Reopen report'), ('FINALIZE_RESPONSE', 'Finalize response'), ('EMERGENCY_EXPORT', 'Emergency export'), ('DELETE_REPORT', 'Delete report'), ('DELETE_REPORT_FLOOD', 'Delete report during flood')], editable=False, max_length=24)),
                ('state', models.CharField(choices=[('PREPARED', 'Prepared'), ('ACTIVE', 'Active'), ('COMPLETED', 'Completed'), ('FAILED', 'Failed'), ('ABORTED', 'Aborted')], default='PREPARED', editable=False, max_length=12)),
                ('state_version', models.PositiveBigIntegerField(default=0, editable=False)),
                ('bound_report_version', models.PositiveBigIntegerField(editable=False)),
                ('fence_token', models.PositiveBigIntegerField(editable=False)),
                ('idempotency_id', models.UUIDField(default=uuid.uuid4, editable=False, unique=True)),
                ('actor_id', models.UUIDField(editable=False)),
                ('lease_generation', models.PositiveBigIntegerField(editable=False, null=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('activated_at', models.DateTimeField(editable=False, null=True)),
                ('terminal_at', models.DateTimeField(editable=False, null=True)),
                ('lease', models.ForeignKey(editable=False, null=True, on_delete=django.db.models.deletion.PROTECT, related_name='security_operations', to='report_lifecycle.reportlease')),
                ('report', models.ForeignKey(editable=False, on_delete=django.db.models.deletion.PROTECT, related_name='security_operations', to='report_lifecycle.report')),
            ],
            options={
                'db_table': 'report_lifecycle_security_operation',
                'default_permissions': (),
            },
        ),
        migrations.AddIndex(
            model_name='reportlease',
            index=models.Index(fields=['state', 'absolute_expires_at'], name='lease_state_expiry_idx'),
        ),
        migrations.AddConstraint(
            model_name='reportlease',
            constraint=models.CheckConstraint(condition=models.Q(('state__in', ['ACTIVE', 'RELEASED', 'EXPIRED', 'INVALIDATED'])), name='lease_known_state'),
        ),
        migrations.AddConstraint(
            model_name='reportlease',
            constraint=models.CheckConstraint(condition=models.Q(('generation__gte', 1)), name='lease_positive_generation'),
        ),
        migrations.AddConstraint(
            model_name='reportlease',
            constraint=models.CheckConstraint(condition=models.Q(('state_version__gte', 0)), name='lease_nonnegative_state_version'),
        ),
        migrations.AddConstraint(
            model_name='reportlease',
            constraint=models.CheckConstraint(condition=models.Q(('last_activity_at__gte', models.F('opened_at')), ('absolute_expires_at__gt', models.F('opened_at')), ('last_activity_at__lt', models.F('absolute_expires_at'))), name='lease_time_order'),
        ),
        migrations.AddConstraint(
            model_name='reportlease',
            constraint=models.CheckConstraint(condition=models.Q(models.Q(('closed_at__isnull', True), ('state', 'ACTIVE')), models.Q(('closed_at__isnull', False), ('state__in', ('RELEASED', 'EXPIRED', 'INVALIDATED'))), _connector='OR'), name='lease_closed_timestamp_shape'),
        ),
        migrations.AddConstraint(
            model_name='reportlease',
            constraint=models.UniqueConstraint(fields=('report', 'generation'), name='one_lease_generation_per_report'),
        ),
        migrations.AddConstraint(
            model_name='reportlease',
            constraint=models.UniqueConstraint(condition=models.Q(('state', 'ACTIVE')), fields=('report',), name='one_active_lease_per_report'),
        ),
        migrations.AddConstraint(
            model_name='reportlease',
            constraint=models.UniqueConstraint(condition=models.Q(('state', 'ACTIVE')), fields=('operator_id',), name='one_active_lease_per_operator'),
        ),
        migrations.AddIndex(
            model_name='securityoperation',
            index=models.Index(fields=['state', 'created_at'], name='operation_state_created_idx'),
        ),
        migrations.AddConstraint(
            model_name='securityoperation',
            constraint=models.CheckConstraint(condition=models.Q(('kind__in', ['REOPEN_REPORT', 'FINALIZE_RESPONSE', 'EMERGENCY_EXPORT', 'DELETE_REPORT', 'DELETE_REPORT_FLOOD'])), name='operation_known_kind'),
        ),
        migrations.AddConstraint(
            model_name='securityoperation',
            constraint=models.CheckConstraint(condition=models.Q(('state__in', ['PREPARED', 'ACTIVE', 'COMPLETED', 'FAILED', 'ABORTED'])), name='operation_known_state'),
        ),
        migrations.AddConstraint(
            model_name='securityoperation',
            constraint=models.CheckConstraint(condition=models.Q(('bound_report_version__gte', 0), ('state_version__gte', 0)), name='operation_nonnegative_versions'),
        ),
        migrations.AddConstraint(
            model_name='securityoperation',
            constraint=models.CheckConstraint(condition=models.Q(('fence_token__gte', 1)), name='operation_positive_fence'),
        ),
        migrations.AddConstraint(
            model_name='securityoperation',
            constraint=models.CheckConstraint(condition=models.Q(models.Q(('lease__isnull', True), ('lease_generation__isnull', True)), models.Q(('lease__isnull', False), ('lease_generation__gte', 1)), _connector='OR'), name='operation_lease_binding_shape'),
        ),
        migrations.AddConstraint(
            model_name='securityoperation',
            constraint=models.CheckConstraint(condition=models.Q(models.Q(('activated_at__isnull', True), ('state', 'PREPARED'), ('terminal_at__isnull', True)), models.Q(('activated_at__isnull', False), ('state', 'ACTIVE'), ('terminal_at__isnull', True)), models.Q(('state__in', ('COMPLETED', 'FAILED', 'ABORTED')), ('terminal_at__isnull', False)), _connector='OR'), name='operation_timestamp_shape'),
        ),
        migrations.AddConstraint(
            model_name='securityoperation',
            constraint=models.UniqueConstraint(fields=('report', 'fence_token'), name='one_operation_fence_token_per_report'),
        ),
        migrations.AddConstraint(
            model_name='securityoperation',
            constraint=models.UniqueConstraint(condition=models.Q(('state', 'ACTIVE')), fields=('report',), name='one_active_operation_per_report'),
        ),
    ]
