"""Audit events table.

Revision ID: 007
Revises: 006
Create Date: 2026-11-25
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "007"
down_revision: Union[str, None] = "006"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "audit_events",
        sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=True),
        sa.Column("username", sa.String(50), nullable=False),
        sa.Column("action", sa.String(50), nullable=False),
        sa.Column("target", sa.String(500), nullable=True),
        sa.Column("detail", sa.JSON(), nullable=True),
        sa.Column("ip", sa.String(64), nullable=True),
        sa.Column("created_at", sa.DateTime(), server_default=sa.text("CURRENT_TIMESTAMP")),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("idx_audit_events_user", "audit_events", ["user_id"])
    op.create_index("idx_audit_events_action", "audit_events", ["action"])
    op.create_index("idx_audit_events_created", "audit_events", ["created_at"])
    op.execute(
        "CREATE INDEX idx_agent_sessions_user_target "
        "ON agent_sessions (user_id, target(191), created_at)"
    )
    op.execute(
        "CREATE INDEX idx_agent_sessions_status_updated "
        "ON agent_sessions (status, updated_at)"
    )


def downgrade() -> None:
    op.execute("DROP INDEX idx_agent_sessions_status_updated ON agent_sessions")
    op.execute("DROP INDEX idx_agent_sessions_user_target ON agent_sessions")
    op.drop_index("idx_audit_events_created", table_name="audit_events")
    op.drop_index("idx_audit_events_action", table_name="audit_events")
    op.drop_index("idx_audit_events_user", table_name="audit_events")
    op.drop_table("audit_events")
