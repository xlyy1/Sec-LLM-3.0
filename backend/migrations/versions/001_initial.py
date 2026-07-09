"""Initial schema — all tables for Sec-LLM Agent Platform.

Revision ID: 001
Revises: None
Create Date: 2026-07-09
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "001"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Users
    op.create_table(
        "users",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("username", sa.String(50), unique=True, nullable=False),
        sa.Column("hashed_password", sa.String(255), nullable=False),
        sa.Column("email", sa.String(100), unique=True, nullable=True),
        sa.Column("full_name", sa.String(100), nullable=True),
        sa.Column("role", sa.String(20), server_default="user"),
        sa.Column("llm_provider", sa.String(20), server_default="local"),
        sa.Column("is_active", sa.Boolean(), server_default=sa.text("FALSE")),
        sa.Column("verification_token", sa.String(255), nullable=True),
        sa.Column("created_at", sa.DateTime(), server_default=sa.text("CURRENT_TIMESTAMP")),
        sa.Column("last_login", sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )

    # Agent Sessions
    op.create_table(
        "agent_sessions",
        sa.Column("id", sa.String(8), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=True),
        sa.Column("target", sa.String(500), nullable=False),
        sa.Column("task_type", sa.String(50), server_default="web_scan"),
        sa.Column("provider", sa.String(20), server_default="local"),
        sa.Column("status", sa.String(20), server_default="running"),
        sa.Column("phase", sa.String(50), nullable=True),
        sa.Column("findings_count", sa.Integer(), server_default="0"),
        sa.Column("steps_completed", sa.Integer(), server_default="0"),
        sa.Column("steps_total", sa.Integer(), server_default="0"),
        sa.Column("report", sa.Text(), nullable=True),
        sa.Column("logs", sa.JSON(), nullable=True),
        sa.Column("created_at", sa.DateTime(), server_default=sa.text("CURRENT_TIMESTAMP")),
        sa.Column("updated_at", sa.DateTime(), server_default=sa.text("CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP")),
        sa.PrimaryKeyConstraint("id"),
    )

    # Agent Findings
    op.create_table(
        "agent_findings",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("session_id", sa.String(8), nullable=False),
        sa.Column("title", sa.String(500), nullable=False),
        sa.Column("severity", sa.String(20), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("evidence", sa.JSON(), nullable=True),
        sa.Column("cve_id", sa.String(50), nullable=True),
        sa.Column("cvss_score", sa.DECIMAL(3, 1), nullable=True),
        sa.Column("file_path", sa.String(500), nullable=True),
        sa.Column("line_number", sa.Integer(), nullable=True),
        sa.Column("fixed_code", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(), server_default=sa.text("CURRENT_TIMESTAMP")),
        sa.ForeignKeyConstraint(["session_id"], ["agent_sessions.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )


def downgrade() -> None:
    op.drop_table("agent_findings")
    op.drop_table("agent_sessions")
    op.drop_table("users")
