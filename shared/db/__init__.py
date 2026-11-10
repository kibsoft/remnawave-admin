"""
Database service package — DatabaseService assembled from mixins.

Usage (backward-compatible):
    from shared.database import db_service
    from shared.db import DatabaseService, db_service
"""
from shared.db._base import DatabaseBase, SCHEMA_SQL, _db_row_to_api_format, _parse_timestamp
from shared.db.users import UsersMixin
from shared.db.nodes import NodesMixin
from shared.db.connections import ConnectionsMixin
from shared.db.violations import ViolationsMixin
from shared.db.resources import ResourcesMixin
from shared.db.network import NetworkMixin
from shared.db.finance import FinanceMixin
from shared.db.finance_accounts import FinanceAccountsMixin
from shared.db.config_versions import ConfigVersionsMixin
from shared.db.user_presets import UserPresetsMixin
from shared.db.bscheck import BscheckMixin
from shared.db.flow_enforcement import FlowEnforcementMixin


class DatabaseService(
    FlowEnforcementMixin,
    UsersMixin,
    NodesMixin,
    ConnectionsMixin,
    ViolationsMixin,
    ResourcesMixin,
    NetworkMixin,
    FinanceMixin,
    FinanceAccountsMixin,
    ConfigVersionsMixin,
    UserPresetsMixin,
    BscheckMixin,
    DatabaseBase,
):
    """Async database service assembled from mixin modules."""
    pass


# Global singleton
db_service = DatabaseService()

__all__ = [
    "DatabaseService",
    "db_service",
    "SCHEMA_SQL",
    "_db_row_to_api_format",
    "_parse_timestamp",
]
