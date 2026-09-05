"""restore tenants table after accidental drop

Revision ID: 533f7411fa79
Revises: 2f51398dc3f8
Create Date: 2026-08-06 09:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision: str = '533f7411fa79'
down_revision: Union[str, Sequence[str], None] = '2f51398dc3f8'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'tenants',
        sa.Column('id', sa.UUID(), autoincrement=False, nullable=False),
        sa.Column('name', sa.VARCHAR(length=128), autoincrement=False, nullable=False),
        sa.Column('slug', sa.VARCHAR(length=64), autoincrement=False, nullable=False),
        sa.Column('is_active', sa.BOOLEAN(), server_default=sa.text('true'), autoincrement=False, nullable=False),
        sa.Column('created_at', postgresql.TIMESTAMP(), server_default=sa.text('now()'), autoincrement=False, nullable=False),
        sa.PrimaryKeyConstraint('id', name=op.f('tenants_pkey')),
        sa.UniqueConstraint('slug', name=op.f('tenants_slug_key')),
    )


def downgrade() -> None:
    op.drop_table('tenants')
