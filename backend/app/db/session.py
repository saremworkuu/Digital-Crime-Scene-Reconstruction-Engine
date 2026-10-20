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

db_url = settings.DATABASE_URL
connect_args = {}

if db_url.startswith("sqlite"):
    connect_args = {"check_same_thread": False}
else:
    # Test PostgreSQL connection; if unavailable on localhost, fallback to SQLite
    try:
        test_engine = create_engine(
            db_url,
            connect_args={"connect_timeout": 2} if "postgresql" in db_url else {}
        )
        with test_engine.connect() as conn:
            pass
        test_engine.dispose()
    except Exception as e:
        logger.warning(
            f"PostgreSQL connection to {db_url} failed ({e}). Falling back to local SQLite database (sqlite:///dcsre.db)."
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