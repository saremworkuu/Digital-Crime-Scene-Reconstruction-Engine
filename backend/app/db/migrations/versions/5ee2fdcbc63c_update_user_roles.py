"""update user roles

Revision ID: 5ee2fdcbc63c
Revises: 7215bc1592e9
Create Date: 2026-10-07 14:15:32.894979

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '5ee2fdcbc63c'
down_revision: Union[str, None] = '7215bc1592e9'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute("""
        ALTER TYPE user_role
        RENAME TO user_role_old;
    """)

    op.execute("""
        CREATE TYPE user_role AS ENUM (
            'admin',
            'investigator',
            'viewer'
        );
    """)

    op.execute("""
        ALTER TABLE users
        ALTER COLUMN role TYPE user_role
        USING role::text::user_role;
    """)

    op.execute("""
        DROP TYPE user_role_old;
    """)


def downgrade() -> None:
    op.execute("""
        ALTER TYPE user_role
        RENAME TO user_role_new;
    """)

    op.execute("""
        CREATE TYPE user_role AS ENUM (
            'admin',
            'analyst'
        );
    """)

    # Convert investigator back to analyst.
    op.execute("""
        ALTER TABLE users
        ALTER COLUMN role TYPE user_role
        USING (
            CASE
                WHEN role::text = 'investigator' THEN 'analyst'
                WHEN role::text = 'viewer' THEN 'analyst'
                ELSE role::text
            END
        )::user_role;
    """)

    op.execute("""
        DROP TYPE user_role_new;
    """)
