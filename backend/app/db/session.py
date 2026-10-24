# Database session
import logging
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.compiler import compiles
from sqlalchemy.dialects.postgresql import UUID, JSONB

from app.core.config import settings

logger = logging.getLogger(__name__)

# Register SQLite compilers for PostgreSQL types so local SQLite works seamlessly
@compiles(UUID, "sqlite")
def compile_uuid_sqlite(type_, compiler, **kw):
    return "VARCHAR(36)"

@compiles(JSONB, "sqlite")
def compile_jsonb_sqlite(type_, compiler, **kw):
    return "JSON"

import socket
from urllib.parse import urlparse

db_url = settings.DATABASE_URL
connect_args = {}

if db_url.startswith("sqlite"):
    connect_args = {"check_same_thread": False}
else:
    # Test socket availability before engine connect to avoid blocking on Windows TCP timeout
    postgres_available = False
    try:
        parsed = urlparse(db_url)
        host = parsed.hostname or "127.0.0.1"
        port = parsed.port or 5432
        with socket.create_connection((host, port), timeout=0.3):
            postgres_available = True
    except Exception:
        postgres_available = False

    if postgres_available:
        try:
            test_engine = create_engine(
                db_url,
                connect_args={"connect_timeout": 1} if "postgresql" in db_url else {}
            )
            with test_engine.connect() as conn:
                pass
            test_engine.dispose()
        except Exception as e:
            postgres_available = False

    if not postgres_available:
        logger.warning(
            f"PostgreSQL server not detected at {db_url}. Using high-performance local SQLite database (sqlite:///dcsre.db)."
        )
        db_url = "sqlite:///dcsre.db"
        connect_args = {"check_same_thread": False}

engine = create_engine(
    db_url,
    connect_args=connect_args
)

SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine
)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()