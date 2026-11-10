"""Per-node exact-flow firewall telemetry (additive, no account actions)."""
from alembic import op
revision = "0128"
down_revision = "0127"
branch_labels = None
depends_on = None

def upgrade():
    op.execute("ALTER TABLE nodes ADD COLUMN IF NOT EXISTS flow_enforcement JSONB")
    op.execute("ALTER TABLE nodes ADD COLUMN IF NOT EXISTS flow_enforcement_received_at TIMESTAMPTZ")

def downgrade():
    op.execute("ALTER TABLE nodes DROP COLUMN IF EXISTS flow_enforcement_received_at")
    op.execute("ALTER TABLE nodes DROP COLUMN IF EXISTS flow_enforcement")
