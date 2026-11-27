import logging
import uuid
from sqlalchemy import text
from app.db.session import engine, SessionLocal
from app.db.base import Base
import app.db.models  # ensure all models registered
from app.db.models.user import User, UserRole
from app.db.seed_admin_data import seed_admin_data
from app.core.security import hash_password

logger = logging.getLogger(__name__)


def migrate_schema():
    """Add new optional columns to existing tables if missing."""
    with engine.connect() as conn:
        dialect = engine.dialect.name
        if dialect == "sqlite":
            tables_cols = [
                ("cases", "legal_hold", "BOOLEAN DEFAULT 0"),
                ("cases", "is_archived", "BOOLEAN DEFAULT 0"),
                ("evidence", "expected_sha256", "VARCHAR(64)"),
                ("evidence", "verified", "BOOLEAN DEFAULT NULL"),
                ("users", "department", "VARCHAR DEFAULT 'Digital Forensic Incident Response (DFIR) Command'"),
                ("users", "badge_id", "VARCHAR DEFAULT NULL"),
                ("users", "two_factor_enabled", "BOOLEAN DEFAULT 0"),
                ("users", "status", "VARCHAR(20) DEFAULT 'active'"),
                ("users", "sessions", "JSON DEFAULT '[]'"),
                ("reports", "version", "VARCHAR(20) DEFAULT '1.0'"),
                ("reports", "generator_name", "VARCHAR DEFAULT 'Lead Forensics Investigator'"),
                ("reports", "report_data", "TEXT DEFAULT NULL"),
            ]
            for table, col, col_def in tables_cols:
                try:
                    res = conn.execute(text(f"PRAGMA table_info({table})")).fetchall()
                    existing_cols = [r[1] for r in res]
                    if col not in existing_cols:
                        conn.execute(text(f"ALTER TABLE {table} ADD COLUMN {col} {col_def}"))
                        conn.commit()
                        logger.info(f"Added column {col} to {table}")
                except Exception as ex:
                    logger.warning(f"Column migration notice for {table}.{col}: {ex}")
        elif dialect == "postgresql":
            alter_statements = [
                "ALTER TABLE cases ADD COLUMN IF NOT EXISTS legal_hold BOOLEAN DEFAULT FALSE, ADD COLUMN IF NOT EXISTS is_archived BOOLEAN DEFAULT FALSE",
                "ALTER TABLE evidence ADD COLUMN IF NOT EXISTS expected_sha256 VARCHAR(64), ADD COLUMN IF NOT EXISTS verified BOOLEAN DEFAULT NULL",
                "ALTER TABLE users ADD COLUMN IF NOT EXISTS department VARCHAR DEFAULT 'Digital Forensic Incident Response (DFIR) Command', ADD COLUMN IF NOT EXISTS badge_id VARCHAR DEFAULT NULL, ADD COLUMN IF NOT EXISTS two_factor_enabled BOOLEAN DEFAULT FALSE, ADD COLUMN IF NOT EXISTS status VARCHAR(20) DEFAULT 'active', ADD COLUMN IF NOT EXISTS sessions JSONB DEFAULT '[]'::jsonb",
                "ALTER TABLE reports ADD COLUMN IF NOT EXISTS version VARCHAR(20) DEFAULT '1.0', ADD COLUMN IF NOT EXISTS generator_name VARCHAR DEFAULT 'Lead Forensics Investigator', ADD COLUMN IF NOT EXISTS report_data TEXT DEFAULT NULL",
            ]
            for stmt in alter_statements:
                try:
                    conn.execute(text(stmt))
                    conn.commit()
                except Exception as ex:
                    conn.rollback()
                    logger.warning(f"PostgreSQL column migration notice: {ex}")


def init_db():
    Base.metadata.create_all(bind=engine)
    migrate_schema()
    db = SessionLocal()
    try:
        # Seed or sync default admin user
        admin_email = "saremworkuu@gmail.com"
        admin = db.query(User).filter(User.email == admin_email).first()
        if not admin:
            admin = User(
                id=uuid.UUID("222c593addec4265b39e1fa7b82eca1e"),
                username="saremworkuu",
                email=admin_email,
                hashed_password=hash_password("Admin@2026!"),
                role=UserRole.ADMIN,
                is_active=True,
                department="Digital Forensic Incident Response (DFIR) Command",
                two_factor_enabled=True,
                status="active",
                sessions=[],
            )
            db.add(admin)
            db.commit()
            logger.info("Seeded default admin user: saremworkuu@gmail.com")

        # Initialize baseline SystemSettings, 2 Inbox messages, and 2 Detection Rules (when empty)
        seed_admin_data(db)
    finally:
        db.close()


if __name__ == "__main__":
    init_db()
    print("Database initialized and seeded successfully.")
