"""Initial OAuth schema."""
from alembic import op
import sqlalchemy as sa

revision = "0001_initial"
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    op.create_table("oauth_clients",
        sa.Column("client_id", sa.String(100), primary_key=True),
        sa.Column("secret_hash", sa.String(200), nullable=False),
        sa.Column("scopes", sa.String(1000), nullable=False),
        sa.Column("default_scopes", sa.String(1000), nullable=False),
        sa.Column("active", sa.Boolean(), nullable=False))
    op.create_table("audit_events",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("created_at", sa.DateTime(timezone=True)),
        sa.Column("event", sa.String(80), nullable=False),
        sa.Column("client_id", sa.String(100)),
        sa.Column("detail", sa.String(255), nullable=False))
    op.create_table("revoked_tokens",
        sa.Column("jti_hash", sa.String(64), primary_key=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False))


def downgrade():
    op.drop_table("revoked_tokens")
    op.drop_table("audit_events")
    op.drop_table("oauth_clients")
