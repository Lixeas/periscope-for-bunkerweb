"""outgoing alerts: channels, state, send log, instance silence

Revision ID: 0005
Revises: 0004
Create Date: 2026-11-04 15:00:00.000000
"""
import sqlalchemy as sa
from alembic import op

revision = '0005'
down_revision = '0004'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table('alert_channels',
                    sa.Column('id', sa.Integer(), nullable=False),
                    sa.Column('name', sa.String(length=64), nullable=False),
                    sa.Column('kind', sa.String(length=8), nullable=False),
                    sa.Column('enabled', sa.Boolean(), nullable=False),
                    sa.Column('lang', sa.String(length=5), server_default='en', nullable=False),
                    sa.Column('events', sa.String(length=64), server_default='down,degraded,certificate', nullable=False),
                    sa.Column('recipients', sa.Text(), server_default='', nullable=False),
                    sa.Column('webhook_url', sa.String(length=512), server_default='', nullable=False),
                    sa.Column('webhook_secret_enc', sa.String(length=512), server_default='', nullable=False),
                    sa.Column('created_at', sa.DateTime(), nullable=False),
                    sa.PrimaryKeyConstraint('id'),
                    sa.UniqueConstraint('name'))
    op.create_table('alert_channel_tags',
                    sa.Column('channel_id', sa.Integer(), nullable=False),
                    sa.Column('tag_id', sa.Integer(), nullable=False),
                    sa.ForeignKeyConstraint(['channel_id'], ['alert_channels.id'], ondelete='CASCADE'),
                    sa.ForeignKeyConstraint(['tag_id'], ['tags.id'], ondelete='CASCADE'),
                    sa.PrimaryKeyConstraint('channel_id', 'tag_id'))
    op.create_table('alert_state',
                    sa.Column('id', sa.Integer(), nullable=False),
                    sa.Column('kind', sa.String(length=8), nullable=False),
                    sa.Column('instance_id', sa.Integer(), nullable=False),
                    sa.Column('subject', sa.String(length=255), nullable=False),
                    sa.Column('notified', sa.String(length=64), nullable=False),
                    sa.Column('pending', sa.String(length=64), nullable=False),
                    sa.Column('pending_count', sa.Integer(), nullable=False),
                    sa.Column('notified_at', sa.DateTime(), nullable=True),
                    sa.ForeignKeyConstraint(['instance_id'], ['instances.id'], ondelete='CASCADE'),
                    sa.PrimaryKeyConstraint('id'),
                    sa.UniqueConstraint('kind', 'instance_id', 'subject'))
    op.create_table('alert_log',
                    sa.Column('id', sa.Integer(), nullable=False),
                    sa.Column('at', sa.DateTime(), nullable=False),
                    sa.Column('channel_id', sa.Integer(), nullable=True),
                    sa.Column('channel_name', sa.String(length=64), nullable=False),
                    sa.Column('events', sa.String(length=255), nullable=False),
                    sa.Column('instances', sa.String(length=255), nullable=False),
                    sa.Column('ok', sa.Boolean(), nullable=False),
                    sa.Column('error', sa.String(length=512), nullable=False),
                    sa.ForeignKeyConstraint(['channel_id'], ['alert_channels.id'], ondelete='SET NULL'),
                    sa.PrimaryKeyConstraint('id'))
    with op.batch_alter_table('instances', schema=None) as batch_op:
        batch_op.add_column(sa.Column('silenced_until', sa.DateTime(), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table('instances', schema=None) as batch_op:
        batch_op.drop_column('silenced_until')
    op.drop_table('alert_log')
    op.drop_table('alert_state')
    op.drop_table('alert_channel_tags')
    op.drop_table('alert_channels')
