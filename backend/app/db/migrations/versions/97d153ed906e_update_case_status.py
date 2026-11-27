"""update case status

Revision ID: 97d153ed906e
Revises: 5ee2fdcbc63c
Create Date: 2026-10-07 14:32:13.494660

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '97d153ed906e'
down_revision: Union[str, None] = '5ee2fdcbc63c'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute(
        "ALTER TYPE case_status ADD VALUE 'in_progress'"
    )

def downgrade() -> None:
    pass
