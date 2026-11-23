"""explanation_trigger_memory

Phase 6.1: restart-stable explanation triggering and a hard raw_response cap.

ai_explanations
  + trigger_key     what triggered the explanation (unique per incident)
  + decision_at     decision time the explanation describes
  + evidence_state  evidence the explanation was based on (JSON)
  + UNIQUE(incident_id, trigger_key) WHERE trigger_key IS NOT NULL
  + INDEX(situation_id, decision_at)
  + CHECK length(raw_response) <= 16000

All new columns are nullable so earlier rows stay valid. Hand-written because
autogenerate does not emit CHECK constraints or partial indexes.

Revision ID: f8b5d2c30008
Revises: e7a4c1b20007
Create Date: 2026-11-18

"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "f8b5d2c30008"
down_revision: str | Sequence[str] | None = "e7a4c1b20007"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Upgrade schema."""
    with op.batch_alter_table("ai_explanations", schema=None) as batch_op:
        batch_op.add_column(sa.Column("trigger_key", sa.Text(), nullable=True))
        batch_op.add_column(sa.Column("decision_at", sa.DateTime(timezone=True), nullable=True))
        batch_op.add_column(sa.Column("evidence_state", sa.Text(), nullable=True))
        batch_op.create_index(
            "uq_ai_explanations_trigger_key",
            ["incident_id", "trigger_key"],
            unique=True,
            sqlite_where=sa.text("trigger_key IS NOT NULL"),
            postgresql_where=sa.text("trigger_key IS NOT NULL"),
        )
        batch_op.create_index(
            "ix_ai_explanations_situation_decision", ["situation_id", "decision_at"], unique=False
        )
        batch_op.create_check_constraint(
            "ck_ai_explanations_raw_response_size",
            "raw_response IS NULL OR length(raw_response) <= 16000",
        )


def downgrade() -> None:
    """Downgrade schema."""
    with op.batch_alter_table("ai_explanations", schema=None) as batch_op:
        batch_op.drop_constraint("ck_ai_explanations_raw_response_size", type_="check")
        batch_op.drop_index("ix_ai_explanations_situation_decision")
        batch_op.drop_index("uq_ai_explanations_trigger_key")
        batch_op.drop_column("evidence_state")
        batch_op.drop_column("decision_at")
        batch_op.drop_column("trigger_key")
