from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    pass


from app.db.models.audit_log import AuditLog
from app.db.models.case import Case
from app.db.models.detection import Detection
from app.db.models.entity import Entity
from app.db.models.event import Event
from app.db.models.evidence import Evidence
from app.db.models.relationship import Relationship
from app.db.models.report import Report
from app.db.models.user import User