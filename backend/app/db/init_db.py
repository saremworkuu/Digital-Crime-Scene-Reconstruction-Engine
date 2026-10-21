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
        # Check and seed Admin user
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

        # Check and seed Investigator user
        inv_email = "investigator@dcsre.corp"
        investigator = db.query(User).filter(User.email == inv_email).first()
        if not investigator:
            investigator = User(
                id=uuid.uuid4(),
                username="investigator",
                email=inv_email,
                hashed_password=hash_password("Investigator#2026"),
                role=UserRole.INVESTIGATOR,
                is_active=True,
            )
            db.add(investigator)
            logger.info("Seeded default investigator user: investigator@dcsre.corp")

        db.commit()

        # Seed initial sample case if none exist
        case_count = db.query(Case).count()
        if case_count == 0 and admin:
            sample_case = Case(
                id=uuid.uuid4(),
                name="Operation Cobalt Shadow (APT Intrusion Analysis)",
                description="Forensic investigation into enterprise unauthorized access, privilege escalation, and lateral movement.",
                status=CaseStatus.OPEN,
                created_by=admin.id,
            )
            db.add(sample_case)
            db.flush()
            if investigator:
                assignment = CaseAssignment(
                    id=uuid.uuid4(),
                    case_id=sample_case.id,
                    user_id=investigator.id,
                    assigned_by=admin.id,
                )
                db.add(assignment)
            db.commit()
            logger.info("Seeded initial case: Operation Cobalt Shadow")
        elif investigator and admin:
            # Ensure investigator is assigned to all active cases for testing
            all_cases = db.query(Case).filter(Case.is_deleted == False).all()
            for c in all_cases:
                existing_assign = db.query(CaseAssignment).filter(
                    CaseAssignment.case_id == c.id,
                    CaseAssignment.user_id == investigator.id,
                ).first()
                if not existing_assign:
                    db.add(CaseAssignment(
                        id=uuid.uuid4(),
                        case_id=c.id,
                        user_id=investigator.id,
                        assigned_by=admin.id,
                    ))
            db.commit()

    finally:
        db.close()


if __name__ == "__main__":
    init_db()
    print("Database initialized and seeded successfully.")
