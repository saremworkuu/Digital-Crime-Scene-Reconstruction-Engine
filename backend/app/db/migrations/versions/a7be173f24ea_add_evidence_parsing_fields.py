"""add evidence parsing fields

Revision ID: a7be173f24ea
Revises: 8fcd66edcb88
Create Date: 2026-10-14 01:31:57.015372

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'a7be173f24ea'
down_revision: Union[str, None] = '8fcd66edcb88'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    parsing_status_enum = sa.Enum(
        "pending",
        "parsed",
        "failed",
        name="evidence_parsing_status",
    )

    parsing_status_enum.create(op.get_bind(), checkfirst=True)

    op.add_column(
        "evidence",
        sa.Column(
            "parsing_status",
            parsing_status_enum,
            nullable=False,
            server_default="pending",
        ),
    )

    op.add_column(
        "evidence",
        sa.Column("parser_used", sa.String(length=100), nullable=True),
    )

    op.add_column(
        "evidence",
        sa.Column("parsing_error", sa.Text(), nullable=True),
    )

    op.alter_column(
        "evidence",
        "description",
        existing_type=sa.TEXT(),
        nullable=True,
    )


def downgrade() -> None:
    op.alter_column(
        "evidence",
        "description",
        existing_type=sa.TEXT(),
        nullable=False,
    )

    op.drop_column("evidence", "parsing_error")
    op.drop_column("evidence", "parser_used")
    op.drop_column("evidence", "parsing_status")

    sa.Enum(
        "pending",
        "parsed",
        "failed",
        name="evidence_parsing_status",
    ).drop(op.get_bind(), checkfirst=True)
