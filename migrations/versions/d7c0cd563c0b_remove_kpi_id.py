"""remove kpi id

Revision ID: d7c0cd563c0b
Revises: 45ff89aba14f
Create Date: 2024-06-21 12:46:06.834497

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'd7c0cd563c0b'
down_revision = '45ff89aba14f'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('merchandiser_performances', schema=None) as batch_op:
        batch_op.drop_constraint('merchandiser_performances_k_p_i_id_fkey', type_='foreignkey')
        batch_op.drop_column('k_p_i_id')

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('merchandiser_performances', schema=None) as batch_op:
        batch_op.add_column(sa.Column('k_p_i_id', sa.INTEGER(), autoincrement=False, nullable=False))
        batch_op.create_foreign_key('merchandiser_performances_k_p_i_id_fkey', 'key_performance_indicators', ['k_p_i_id'], ['id'])

    # ### end Alembic commands ###
