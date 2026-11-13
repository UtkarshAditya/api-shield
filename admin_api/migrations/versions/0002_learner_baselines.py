"""learner baselines

Revision ID: 0002
Revises: 0001
Create Date: 2026-11-13 18:00:00
"""
from alembic import op
import sqlalchemy as sa
import admin_api.db


revision = '0002'
down_revision = '0001'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table('learner_baselines',
    sa.Column('upstream_id', sa.String(length=64), nullable=False),
    sa.Column('snapshot', sa.JSON(), nullable=False),
    sa.Column('tuning', sa.JSON(), nullable=False),
    sa.Column('updated_at', admin_api.db.UTCDateTime(), nullable=False),
    sa.PrimaryKeyConstraint('upstream_id')
    )


def downgrade() -> None:
    op.drop_table('learner_baselines')
