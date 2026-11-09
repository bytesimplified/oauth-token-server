"""Add per-client resource audiences for databases already at revision 0001."""
from alembic import op
import sqlalchemy as sa

revision = "0002_resources"
down_revision = "0001_initial"
branch_labels = None
depends_on = None


def upgrade():
    # Existing deployments add the column; fresh databases already have it
    # only if their 0001 migration was modified, so guard via inspection.
    bind = op.get_bind()
    columns = {c["name"] for c in sa.inspect(bind).get_columns("oauth_clients")}
    if "resources" not in columns:
        op.add_column("oauth_clients", sa.Column("resources", sa.String(1000), nullable=False, server_default="orders-api"))


def downgrade():
    op.drop_column("oauth_clients", "resources")
