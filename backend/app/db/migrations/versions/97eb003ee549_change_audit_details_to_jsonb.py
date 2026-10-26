"""change audit details to jsonb

Revision ID: 97eb003ee549
Revises: 1e17b72d1aeb
Create Date: 2026-10-17 12:16:51.682711

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = '97eb003ee549'
down_revision: Union[str, None] = '1e17b72d1aeb'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.alter_column(
        "audit_log",
        "details",
        existing_type=sa.TEXT(),
        type_=postgresql.JSONB(astext_type=sa.Text()),
        existing_nullable=True,
        postgresql_using="details::jsonb",
    )


def downgrade() -> None:
    op.alter_column(
        "audit_log",
        "details",
        existing_type=postgresql.JSONB(astext_type=sa.Text()),
        type_=sa.TEXT(),
        existing_nullable=True,
        postgresql_using="details::text",
    )