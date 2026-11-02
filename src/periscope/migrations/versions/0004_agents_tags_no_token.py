"""agent connection mode, instance tags, settings; static API token mode removed

Revision ID: 0004
Revises: 0003
Create Date: 2026-11-02 09:00:00.000000

Instances that used the static API token (auth_mode = 'token') cannot be converted automatically:
they are kept as `direct` instances, disabled, with a stored message asking for an API user.
"""
import sqlalchemy as sa
from alembic import op

from periscope.i18n import pack

revision = '0004'
down_revision = '0003'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table('tags',
                    sa.Column('id', sa.Integer(), nullable=False),
                    sa.Column('name', sa.String(length=32), nullable=False),
                    sa.PrimaryKeyConstraint('id'),
                    sa.UniqueConstraint('name'))
    op.create_table('instance_tags',
                    sa.Column('instance_id', sa.Integer(), nullable=False),
                    sa.Column('tag_id', sa.Integer(), nullable=False),
                    sa.ForeignKeyConstraint(['instance_id'], ['instances.id'], ondelete='CASCADE'),
                    sa.ForeignKeyConstraint(['tag_id'], ['tags.id'], ondelete='CASCADE'),
                    sa.PrimaryKeyConstraint('instance_id', 'tag_id'))
    op.create_table('settings',
                    sa.Column('key', sa.String(length=64), nullable=False),
                    sa.Column('value', sa.Text(), nullable=False),
                    sa.PrimaryKeyConstraint('key'))
    with op.batch_alter_table('instances', schema=None) as batch_op:
        batch_op.add_column(sa.Column('connection', sa.String(length=8), server_default='direct', nullable=False))
        batch_op.add_column(sa.Column('agent_cert_fp', sa.String(length=64), server_default='', nullable=False))
        batch_op.add_column(sa.Column('agent_cert_not_after', sa.DateTime(), nullable=True))
        batch_op.add_column(sa.Column('agent_next_cert_fp', sa.String(length=64), server_default='', nullable=False))
        batch_op.add_column(sa.Column('agent_enroll_hash', sa.String(length=64), server_default='', nullable=False))
        batch_op.add_column(sa.Column('agent_enroll_expires', sa.DateTime(), nullable=True))
        batch_op.add_column(sa.Column('agent_ip', sa.String(length=64), server_default='', nullable=False))
        batch_op.add_column(sa.Column('agent_version', sa.String(length=32), server_default='', nullable=False))
        batch_op.alter_column('base_url', server_default='')
    message = pack("The static API token is no longer supported: edit this instance and enter an API user.")
    op.get_bind().execute(
        sa.text("UPDATE instances SET enabled = :off, status = 'unknown', last_error = :msg, "
                "api_username = '', api_password_enc = '' WHERE auth_mode = 'token'"),
        {"off": False, "msg": message})
    with op.batch_alter_table('instances', schema=None) as batch_op:
        batch_op.drop_column('token_enc')
        batch_op.drop_column('auth_mode')


def downgrade() -> None:
    with op.batch_alter_table('instances', schema=None) as batch_op:
        batch_op.add_column(sa.Column('auth_mode', sa.String(length=8), server_default='user', nullable=False))
        batch_op.add_column(sa.Column('token_enc', sa.String(length=512), server_default='', nullable=False))
    op.get_bind().execute(sa.text("DELETE FROM instances WHERE connection = 'agent'"))
    with op.batch_alter_table('instances', schema=None) as batch_op:
        for col in ('agent_version', 'agent_ip', 'agent_enroll_expires', 'agent_enroll_hash',
                    'agent_next_cert_fp', 'agent_cert_not_after', 'agent_cert_fp', 'connection'):
            batch_op.drop_column(col)
    op.drop_table('settings')
    op.drop_table('instance_tags')
    op.drop_table('tags')
