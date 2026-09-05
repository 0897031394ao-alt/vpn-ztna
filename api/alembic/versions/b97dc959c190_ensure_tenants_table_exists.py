"""ensure tenants table exists

Revision ID: b97dc959c190
Revises: 022ca9aafad2
Create Date: 2026-05-16 13:25:00

"""
from typing import Sequence, Union

from alembic import op

revision: str = "b97dc959c190"
down_revision: Union[str, Sequence[str], None] = "022ca9aafad2"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute("""
    CREATE TABLE IF NOT EXISTS tenants (
        id UUID PRIMARY KEY,
        name VARCHAR(128) NOT NULL,
        slug VARCHAR(64) NOT NULL UNIQUE,
        is_active BOOLEAN NOT NULL DEFAULT TRUE,
        created_at TIMESTAMP WITHOUT TIME ZONE NOT NULL DEFAULT now()
    )
    """)


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS tenants")
