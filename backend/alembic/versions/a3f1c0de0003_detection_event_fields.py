"""detection_event_fields

Phase 3: structured detection results.

Adds telemetry correlation, event type, classification, confidence and
status to detection_events, with CHECK constraints. Alembic autogenerate
does not emit CHECK constraints or constraint names, so this revision is
hand-written to match database/models.py.

Existing rows (none in a fresh install) receive the server defaults.

Revision ID: a3f1c0de0003
Revises: 532f8b0b7293
Create Date: 2026-11-18

"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "a3f1c0de0003"
down_revision: str | Sequence[str] | None = "532f8b0b7293"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_SEVERITY_CHECK = "severity IN ('INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL')"
_CLASSIFICATION_CHECK = "classification IN ('INFORMATIONAL', 'SUSPICIOUS', 'HIGH_CONFIDENCE')"
_STATUS_CHECK = "status IN ('open')"
_CONFIDENCE_CHECK = "confidence IS NULL OR (confidence >= 0.0 AND confidence <= 1.0)"


def upgrade() -> None:
    """Upgrade schema."""
    with op.batch_alter_table("detection_events", schema=None) as batch_op:
        batch_op.add_column(sa.Column("telemetry_sample_id", sa.Integer(), nullable=True))
        batch_op.add_column(
            sa.Column("event_type", sa.Text(), server_default="unspecified", nullable=False)
        )
        batch_op.add_column(
            sa.Column("classification", sa.Text(), server_default="INFORMATIONAL", nullable=False)
        )
        batch_op.add_column(sa.Column("confidence", sa.Float(), nullable=True))
        batch_op.add_column(sa.Column("status", sa.Text(), server_default="open", nullable=False))
        batch_op.create_index(
            "ix_detection_events_telemetry_sample_id", ["telemetry_sample_id"], unique=False
        )
        batch_op.create_foreign_key(
            "fk_detection_events_telemetry_sample_id",
            "telemetry_samples",
            ["telemetry_sample_id"],
            ["id"],
            ondelete="SET NULL",
        )
        batch_op.create_check_constraint("ck_detection_events_severity", _SEVERITY_CHECK)
        batch_op.create_check_constraint(
            "ck_detection_events_classification", _CLASSIFICATION_CHECK
        )
        batch_op.create_check_constraint("ck_detection_events_status", _STATUS_CHECK)
        batch_op.create_check_constraint("ck_detection_events_confidence_range", _CONFIDENCE_CHECK)


def downgrade() -> None:
    """Downgrade schema."""
    with op.batch_alter_table("detection_events", schema=None) as batch_op:
        batch_op.drop_constraint("ck_detection_events_confidence_range", type_="check")
        batch_op.drop_constraint("ck_detection_events_status", type_="check")
        batch_op.drop_constraint("ck_detection_events_classification", type_="check")
        batch_op.drop_constraint("ck_detection_events_severity", type_="check")
        batch_op.drop_constraint("fk_detection_events_telemetry_sample_id", type_="foreignkey")
        batch_op.drop_index("ix_detection_events_telemetry_sample_id")
        batch_op.drop_column("status")
        batch_op.drop_column("confidence")
        batch_op.drop_column("classification")
        batch_op.drop_column("event_type")
        batch_op.drop_column("telemetry_sample_id")
