import logging
import uuid
from sqlalchemy import text
from app.db.session import engine, SessionLocal
from app.db.base import Base
import app.db.models  # ensure all models registered
from app.db.models.user import User, UserRole
from app.core.security import hash_password
from app.db.seed_admin_data import seed_admin_data

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
            tables_cols = [
                ("cases", "legal_hold", "BOOLEAN DEFAULT FALSE"),
                ("cases", "is_archived", "BOOLEAN DEFAULT FALSE"),
                ("evidence", "expected_sha256", "VARCHAR(64)"),
                ("evidence", "verified", "BOOLEAN DEFAULT NULL"),
                ("users", "department", "VARCHAR DEFAULT 'Digital Forensic Incident Response (DFIR) Command'"),
                ("users", "badge_id", "VARCHAR DEFAULT NULL"),
                ("users", "two_factor_enabled", "BOOLEAN DEFAULT FALSE"),
                ("users", "status", "VARCHAR(20) DEFAULT 'active'"),
                ("users", "sessions", "JSONB DEFAULT '[]'::jsonb"),
            ]
            for table, col, col_def in tables_cols:
                try:
                    conn.execute(text(f"ALTER TABLE {table} ADD COLUMN IF NOT EXISTS {col} {col_def}"))
                    conn.commit()
                except Exception as ex:
                    logger.warning(f"PostgreSQL column migration notice for {table}.{col}: {ex}")


def init_db():
    migrate_schema()
    Base.metadata.create_all(bind=engine)
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
                sessions=[
                    {"id": "sess-01", "device": "Chrome 122 on macOS (Arm64)", "ip": "192.168.1.104", "last_active": "Just now"},
                    {"id": "sess-02", "device": "Forensic Lab Workstation 01", "ip": "10.0.4.15", "last_active": "2 hours ago"}
                ]
            )
            db.add(admin)
            db.commit()
            logger.info("Seeded default admin user: saremworkuu@gmail.com")

        # Seed all admin dashboard seed records
        seed_admin_data(db)
        logger.info("Admin seed data initialized successfully.")
    finally:
        db.close()


if __name__ == "__main__":
    init_db()
    print("Database initialized and seeded successfully.")
