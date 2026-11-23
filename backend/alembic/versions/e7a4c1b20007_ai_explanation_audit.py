"""ai_explanation_audit

Phase 6: explanation audit records.

ai_explanations
  + situation_id, trigger, status, failure_reason, failure_detail, latency_ms,
    attempts, context_fingerprint, content (validated JSON)
  + CHECK status  IN ('VALID', 'REJECTED', 'FAILED')
  + CHECK trigger IN (the ExplanationTrigger values)
  + CHECK content is NULL unless status = 'VALID'

All new columns are nullable so earlier rows stay valid. Hand-written because
autogenerate does not emit CHECK constraints.

Revision ID: e7a4c1b20007
Revises: d6f3b9a40006
Create Date: 2026-11-18

"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "e7a4c1b20007"
down_revision: str | Sequence[str] | None = "d6f3b9a40006"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_TRIGGERS = "('INCIDENT_CREATED', 'STATE_TRANSITION', 'NEW_EVIDENCE', 'AGGRESSIVE_REFRESH')"


def upgrade() -> None:
    """Upgrade schema."""
    with op.batch_alter_table("ai_explanations", schema=None) as batch_op:
        batch_op.add_column(sa.Column("situation_id", sa.Integer(), nullable=True))
        batch_op.add_column(sa.Column("trigger", sa.Text(), nullable=True))
        batch_op.add_column(sa.Column("status", sa.Text(), nullable=True))
        batch_op.add_column(sa.Column("failure_reason", sa.Text(), nullable=True))
        batch_op.add_column(sa.Column("failure_detail", sa.Text(), nullable=True))
        batch_op.add_column(sa.Column("latency_ms", sa.Integer(), nullable=True))
        batch_op.add_column(sa.Column("attempts", sa.Integer(), nullable=True))
        batch_op.add_column(sa.Column("context_fingerprint", sa.Text(), nullable=True))
        batch_op.add_column(sa.Column("content", sa.Text(), nullable=True))
        batch_op.create_check_constraint(
            "ck_ai_explanations_status",
            "status IS NULL OR status IN ('VALID', 'REJECTED', 'FAILED')",
        )
        batch_op.create_check_constraint(
            "ck_ai_explanations_trigger", f"trigger IS NULL OR trigger IN {_TRIGGERS}"
        )
        batch_op.create_check_constraint(
            "ck_ai_explanations_content_only_when_valid",
            "status IS NULL OR status = 'VALID' OR content IS NULL",
        )


def downgrade() -> None:
    """Downgrade schema."""
    with op.batch_alter_table("ai_explanations", schema=None) as batch_op:
        batch_op.drop_constraint("ck_ai_explanations_content_only_when_valid", type_="check")
        batch_op.drop_constraint("ck_ai_explanations_trigger", type_="check")
        batch_op.drop_constraint("ck_ai_explanations_status", type_="check")
        batch_op.drop_column("content")
        batch_op.drop_column("context_fingerprint")
        batch_op.drop_column("attempts")
        batch_op.drop_column("latency_ms")
        batch_op.drop_column("failure_detail")
        batch_op.drop_column("failure_reason")
        batch_op.drop_column("status")
        batch_op.drop_column("trigger")
        batch_op.drop_column("situation_id")
