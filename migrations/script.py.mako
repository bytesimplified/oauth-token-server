"""\u0024{message}

Revision ID: \u0024{up_revision}
Revises: \u0024{down_revision | comma,n}
"""
from alembic import op
import sqlalchemy as sa

revision = \u0024{repr(up_revision)}
down_revision = \u0024{repr(down_revision)}
branch_labels = \u0024{repr(branch_labels)}
depends_on = \u0024{repr(depends_on)}


def upgrade():
    \u0024{upgrades if upgrades else "pass"}


def downgrade():
    \u0024{downgrades if downgrades else "pass"}
