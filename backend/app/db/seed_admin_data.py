import logging
from sqlalchemy.orm import Session
from app.db.models.system_settings import SystemSettings

logger = logging.getLogger(__name__)


def seed_admin_data(db: Session):
    """Ensure only baseline system settings exist; never seed fake users, rules, or messages."""
    settings = db.query(SystemSettings).filter(SystemSettings.id == "default").first()
    if not settings:
        settings = SystemSettings(
            id="default",
            time_zone="UTC",
            org_name="አሻራ Cyber Forensic Command",
            retention_days=90,
            min_password_length=12,
            two_factor_enforced=False,
            failed_login_lockout_limit=5,
        )
        db.add(settings)
        db.commit()
        logger.info("Initialized default SystemSettings configuration.")
