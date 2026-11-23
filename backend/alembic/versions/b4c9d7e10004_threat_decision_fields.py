"""threat_decision_fields

Phase 4: explainable threat scores and persisted state transitions.

threat_scores
  + defense_state, breakdown (JSON); CHECK score in [0, 1], valid state.
defense_state_changes
  + previous_score, reason, evidence (JSON); CHECKs for valid states, a real
    transition (previous_state <> new_state), and scores within [0, 1].

Hand-written because Alembic autogenerate does not emit CHECK constraints.
Existing rows must already satisfy the constraints; both tables are written
only by the Phase 4 service, so a fresh install has no rows to violate them.

Revision ID: b4c9d7e10004
Revises: a3f1c0de0003
Create Date: 2026-11-18

"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "b4c9d7e10004"
down_revision: str | Sequence[str] | None = "a3f1c0de0003"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_STATES = "('RELAXED', 'ALERT', 'DEFENSIVE', 'AGGRESSIVE')"


def upgrade() -> None:
    """Upgrade schema."""
    with op.batch_alter_table("threat_scores", schema=None) as batch_op:
        batch_op.add_column(sa.Column("defense_state", sa.Text(), nullable=True))
        batch_op.add_column(sa.Column("breakdown", sa.Text(), nullable=True))
        batch_op.create_check_constraint("ck_threat_scores_range", "score >= 0.0 AND score <= 1.0")
        batch_op.create_check_constraint(
            "ck_threat_scores_state", f"defense_state IS NULL OR defense_state IN {_STATES}"
        )

    with op.batch_alter_table("defense_state_changes", schema=None) as batch_op:
        batch_op.add_column(sa.Column("previous_score", sa.Float(), nullable=True))
        batch_op.add_column(sa.Column("reason", sa.Text(), nullable=True))
        batch_op.add_column(sa.Column("evidence", sa.Text(), nullable=True))
        batch_op.create_check_constraint(
            "ck_defense_state_changes_from", f"previous_state IN {_STATES}"
        )
        batch_op.create_check_constraint("ck_defense_state_changes_to", f"new_state IN {_STATES}")
        batch_op.create_check_constraint(
            "ck_defense_state_changes_is_transition", "previous_state <> new_state"
        )
        batch_op.create_check_constraint(
            "ck_defense_state_changes_trigger_score",
            "trigger_score >= 0.0 AND trigger_score <= 1.0",
        )
        batch_op.create_check_constraint(
            "ck_defense_state_changes_previous_score",
            "previous_score IS NULL OR (previous_score >= 0.0 AND previous_score <= 1.0)",
        )


def downgrade() -> None:
    """Downgrade schema."""
    with op.batch_alter_table("defense_state_changes", schema=None) as batch_op:
        batch_op.drop_constraint("ck_defense_state_changes_previous_score", type_="check")
        batch_op.drop_constraint("ck_defense_state_changes_trigger_score", type_="check")
        batch_op.drop_constraint("ck_defense_state_changes_is_transition", type_="check")
        batch_op.drop_constraint("ck_defense_state_changes_to", type_="check")
        batch_op.drop_constraint("ck_defense_state_changes_from", type_="check")
        batch_op.drop_column("evidence")
        batch_op.drop_column("reason")
        batch_op.drop_column("previous_score")

    with op.batch_alter_table("threat_scores", schema=None) as batch_op:
        batch_op.drop_constraint("ck_threat_scores_state", type_="check")
        batch_op.drop_constraint("ck_threat_scores_range", type_="check")
        batch_op.drop_column("breakdown")
        batch_op.drop_column("defense_state")
