# Database session
import logging
import os
import socket
import time
from urllib.parse import urlparse

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

db_url = settings.DATABASE_URL
connect_args = {}

if db_url.startswith("sqlite"):
    connect_args = {"check_same_thread": False}
else:
    parsed = urlparse(db_url)
    host = parsed.hostname or "127.0.0.1"
    port = parsed.port or 5432
    is_local_host = host in ("127.0.0.1", "localhost", "::1")
    is_deployed = bool(os.getenv("RENDER") or os.getenv("RAILWAY_ENVIRONMENT") or os.getenv("FLY_APP_NAME"))
    tcp_timeout = 2.0 if is_local_host else 6.0
    pg_timeout = 2 if is_local_host else 10

    postgres_available = is_deployed
    if not is_deployed:
        for attempt in range(2):
            try:
                with socket.create_connection((host, port), timeout=tcp_timeout):
                    postgres_available = True
                test_engine = create_engine(
                    db_url,
                    connect_args={"connect_timeout": pg_timeout} if "postgresql" in db_url else {}
                )
                with test_engine.connect():
                    pass
                test_engine.dispose()
                break
            except Exception:
                postgres_available = False
                if attempt == 0 and not is_local_host:
                    time.sleep(1.0)

    if not postgres_available:
        logger.warning(
            f"PostgreSQL server not detected at {db_url}. Using high-performance local SQLite database (sqlite:///dcsre.db)."
        )
        db_url = "sqlite:///dcsre.db"
        connect_args = {"check_same_thread": False}
    elif "postgresql" in db_url:
        connect_args = {"connect_timeout": pg_timeout}

if db_url.startswith("sqlite"):
    engine = create_engine(
        db_url,
        connect_args=connect_args,
    )
else:
    # Avoid extra per-request SELECT 1 roundtrips across remote Postgres connections;
    # recycle pooled connections before server idle timeout.
    engine = create_engine(
        db_url,
        connect_args=connect_args,
        pool_pre_ping=is_deployed,
        pool_size=10,
        max_overflow=20,
        pool_recycle=180,
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