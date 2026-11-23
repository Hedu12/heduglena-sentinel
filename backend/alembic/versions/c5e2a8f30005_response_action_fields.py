"""response_action_fields

Phase 5: response engine audit records.

response_actions
  + situation_id, status, action_class, guard_reason, scope_key, once_key,
    idempotency_key, lifecycle (JSON)
  + UNIQUE(idempotency_key)                         one row per (scope, decision)
  + UNIQUE(once_key) WHERE status = 'SUCCEEDED'     a once-per-scope action succeeds once
  + CHECKs: terminal status, valid action class, valid defense state

All new columns are nullable so rows written before Phase 5 stay valid; the
response service always populates them. Hand-written because autogenerate does
not emit CHECK constraints or partial indexes.

Revision ID: c5e2a8f30005
Revises: b4c9d7e10004
Create Date: 2026-11-18

"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "c5e2a8f30005"
down_revision: str | Sequence[str] | None = "b4c9d7e10004"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_CLASSES = "('INFORMATIONAL', 'MONITORING', 'SIMULATED_PROTECTIVE', 'LIVE_PROTECTIVE')"
_STATES = "('RELAXED', 'ALERT', 'DEFENSIVE', 'AGGRESSIVE')"


def upgrade() -> None:
    """Upgrade schema."""
    with op.batch_alter_table("response_actions", schema=None) as batch_op:
        batch_op.add_column(sa.Column("situation_id", sa.Integer(), nullable=True))
        batch_op.add_column(sa.Column("status", sa.Text(), nullable=True))
        batch_op.add_column(sa.Column("action_class", sa.Text(), nullable=True))
        batch_op.add_column(sa.Column("guard_reason", sa.Text(), nullable=True))
        batch_op.add_column(sa.Column("scope_key", sa.Text(), nullable=True))
        batch_op.add_column(sa.Column("once_key", sa.Text(), nullable=True))
        batch_op.add_column(sa.Column("idempotency_key", sa.Text(), nullable=True))
        batch_op.add_column(sa.Column("lifecycle", sa.Text(), nullable=True))
        batch_op.create_index("ix_response_actions_scope_key", ["scope_key"], unique=False)
        batch_op.create_index("ix_response_actions_situation_id", ["situation_id"], unique=False)
        batch_op.create_index(
            "uq_response_actions_idempotency_key", ["idempotency_key"], unique=True
        )
        batch_op.create_index(
            "uq_response_actions_once_success",
            ["once_key"],
            unique=True,
            sqlite_where=sa.text("status = 'SUCCEEDED'"),
            postgresql_where=sa.text("status = 'SUCCEEDED'"),
        )
        batch_op.create_check_constraint(
            "ck_response_actions_terminal_status",
            "status IS NULL OR status IN ('BLOCKED', 'SUCCEEDED', 'FAILED')",
        )
        batch_op.create_check_constraint(
            "ck_response_actions_action_class",
            f"action_class IS NULL OR action_class IN {_CLASSES}",
        )
        batch_op.create_check_constraint(
            "ck_response_actions_defense_state", f"defense_state IN {_STATES}"
        )


def downgrade() -> None:
    """Downgrade schema."""
    with op.batch_alter_table("response_actions", schema=None) as batch_op:
        batch_op.drop_constraint("ck_response_actions_defense_state", type_="check")
        batch_op.drop_constraint("ck_response_actions_action_class", type_="check")
        batch_op.drop_constraint("ck_response_actions_terminal_status", type_="check")
        batch_op.drop_index("uq_response_actions_once_success")
        batch_op.drop_index("uq_response_actions_idempotency_key")
        batch_op.drop_index("ix_response_actions_situation_id")
        batch_op.drop_index("ix_response_actions_scope_key")
        batch_op.drop_column("lifecycle")
        batch_op.drop_column("idempotency_key")
        batch_op.drop_column("once_key")
        batch_op.drop_column("scope_key")
        batch_op.drop_column("guard_reason")
        batch_op.drop_column("action_class")
        batch_op.drop_column("status")
        batch_op.drop_column("situation_id")
