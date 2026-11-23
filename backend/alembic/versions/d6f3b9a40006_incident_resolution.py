"""incident_resolution

Incident lifecycle: an incident is resolved when its security situation is over
for good.

incidents
  + recovered_at  when the defense state returned to RELAXED
  + resolved_at   when Sentinel confirmed the situation was over
  + resolution    machine-readable reason (QUIET_FOR_REOPEN_WINDOW, ...)
  + CHECK status IN ('open', 'investigating', 'resolved')

All new columns are nullable; existing incidents stay open. Hand-written because
autogenerate does not emit CHECK constraints.

Revision ID: d6f3b9a40006
Revises: c5e2a8f30005
Create Date: 2026-11-18

"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "d6f3b9a40006"
down_revision: str | Sequence[str] | None = "c5e2a8f30005"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Upgrade schema."""
    with op.batch_alter_table("incidents", schema=None) as batch_op:
        batch_op.add_column(sa.Column("recovered_at", sa.DateTime(timezone=True), nullable=True))
        batch_op.add_column(sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True))
        batch_op.add_column(sa.Column("resolution", sa.Text(), nullable=True))
        batch_op.create_check_constraint(
            "ck_incidents_status", "status IN ('open', 'investigating', 'resolved')"
        )


def downgrade() -> None:
    """Downgrade schema."""
    with op.batch_alter_table("incidents", schema=None) as batch_op:
        batch_op.drop_constraint("ck_incidents_status", type_="check")
        batch_op.drop_column("resolution")
        batch_op.drop_column("resolved_at")
        batch_op.drop_column("recovered_at")
