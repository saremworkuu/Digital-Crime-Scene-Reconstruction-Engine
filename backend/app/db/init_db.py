import logging
import uuid
from app.db.session import engine, SessionLocal
from app.db.base import Base
from app.db.models.user import User, UserRole
from app.db.models.case import Case, CaseStatus
from app.db.models.case_assignment import CaseAssignment
from app.core.security import hash_password

logger = logging.getLogger(__name__)

def init_db():
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        # Check and seed Admin user only
        admin_email = "saremworkuu@gmail.com"
        admin = db.query(User).filter(User.email == admin_email).first()
        if not admin:
            admin = User(
                id=uuid.uuid4(),
                username="saremworkuu",
                email=admin_email,
                hashed_password=hash_password("Admin@2026!"),
                role=UserRole.ADMIN,
                is_active=True,
            )
            db.add(admin)
            logger.info("Seeded default admin user: saremworkuu@gmail.com")

        db.commit()
    finally:
        db.close()


if __name__ == "__main__":
    init_db()
    print("Database initialized and seeded successfully.")
