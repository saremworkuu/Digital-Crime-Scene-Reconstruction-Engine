import re
import uuid
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from app.services.ioc_validation import normalize_ioc_value

Severity = Literal["low", "medium", "high", "critical"]
CaseStatus = Literal["open", "in_progress", "closed"]
IRPhase = Literal["identify", "contain", "eradicate", "recover", "lessons"]
TaskStatus = Literal["todo", "in_progress", "done", "skipped"]
IOCStatus = Literal["observed", "blocked", "monitoring", "false_positive"]
IOCType = Literal["ip", "domain", "hash", "user", "host", "email", "url"]

# INC-2026-0042 or CASE-2026-0001 style identifiers
CASE_ID_PATTERN = re.compile(r"^[A-Z]{2,8}-\d{4}-\d{3,6}$")
# Investigation title: letters only (spaces between words OK), ≥2 letters
TITLE_PATTERN = re.compile(r"^[A-Za-z]+(?:\s+[A-Za-z]+)*$")


def normalize_investigation_title(value: str) -> str:
    cleaned = " ".join(value.split())
    letters = re.sub(r"[^A-Za-z]", "", cleaned)
    if len(letters) < 2 or not TITLE_PATTERN.match(cleaned):
        raise ValueError(
            "title must be letters only (spaces OK) and at least 2 letters"
        )
    return cleaned


class ORMModel(BaseModel):
    model_config = ConfigDict(from_attributes=True)


# --- Cases ---


class CaseCreate(BaseModel):
    case_id: str = Field(..., examples=["INC-2026-0042"])
    title: str
    description: str = ""
    created_by: uuid.UUID | None = None

    @field_validator("case_id")
    @classmethod
    def normalize_case_id(cls, value: str) -> str:
        cleaned = value.strip().upper()
        if not CASE_ID_PATTERN.match(cleaned):
            raise ValueError(
                "case_id must look like INC-2026-0042 (PREFIX-YEAR-NUMBER)"
            )
        return cleaned

    @field_validator("title")
    @classmethod
    def normalize_title(cls, value: str) -> str:
        return normalize_investigation_title(value)


class CaseUpdate(BaseModel):
    case_id: str | None = None
    title: str | None = None
    description: str | None = None
    status: CaseStatus | None = None

    @field_validator("case_id")
    @classmethod
    def normalize_case_id(cls, value: str | None) -> str | None:
        if value is None:
            return value
        cleaned = value.strip().upper()
        if not CASE_ID_PATTERN.match(cleaned):
            raise ValueError(
                "case_id must look like INC-2026-0042 (PREFIX-YEAR-NUMBER)"
            )
        return cleaned

    @field_validator("title")
    @classmethod
    def normalize_title(cls, value: str | None) -> str | None:
        if value is None:
            return value
        return normalize_investigation_title(value)


class CaseOut(ORMModel):
    id: uuid.UUID
    case_id: str
    title: str
    description: str
    status: CaseStatus
    created_by: uuid.UUID
    created_at: datetime
    updated_at: datetime


class CaseNoteCreate(BaseModel):
    author: str = "analyst"
    body: str


class CaseNoteOut(ORMModel):
    id: int
    case_id: uuid.UUID
    author: str
    body: str
    created_at: datetime


# --- Playbooks / Tasks ---


class PlaybookStepOut(ORMModel):
    id: int
    order_index: int
    phase: str
    title: str
    guidance: str
    recommended_action: str


class PlaybookOut(ORMModel):
    id: int
    name: str
    incident_type: str
    description: str
    steps: list[PlaybookStepOut] = Field(default_factory=list)


class ApplyPlaybookRequest(BaseModel):
    playbook_id: int
    owner: str = "unassigned"


class TaskCreate(BaseModel):
    phase: IRPhase
    title: str
    guidance: str = ""
    recommended_action: str = ""
    owner: str = "unassigned"
    linked_event_id: int | None = None
    linked_ioc_id: int | None = None


class TaskUpdate(BaseModel):
    status: TaskStatus | None = None
    owner: str | None = None
    title: str | None = None
    guidance: str | None = None
    recommended_action: str | None = None
    linked_event_id: int | None = None
    linked_ioc_id: int | None = None


class TaskOut(ORMModel):
    id: int
    case_id: uuid.UUID
    playbook_step_id: int | None
    phase: str
    title: str
    guidance: str
    recommended_action: str
    status: str
    owner: str
    linked_event_id: int | None
    linked_ioc_id: int | None
    completed_at: datetime | None
    created_at: datetime


# --- IOCs ---


class IOCCreate(BaseModel):
    ioc_type: IOCType
    value: str
    status: IOCStatus = "observed"
    severity: Severity = "medium"
    notes: str = ""
    recommended_response: str = ""

    @model_validator(mode="after")
    def validate_value_for_type(self) -> "IOCCreate":
        self.value = normalize_ioc_value(self.ioc_type, self.value)
        return self


class IOCUpdate(BaseModel):
    status: IOCStatus | None = None
    severity: Severity | None = None
    notes: str | None = None
    recommended_response: str | None = None


class IOCOut(ORMModel):
    id: int
    case_id: uuid.UUID
    ioc_type: str
    value: str
    status: str
    severity: str
    notes: str
    recommended_response: str
    created_at: datetime


# --- Techniques ---


class TechniqueCreate(BaseModel):
    mitre_id: str = ""
    name: str = ""
    tactic: str = ""
    confidence: float = 0.7
    evidence_summary: str = ""
    linked_event_id: int | None = None


class TechniqueOut(ORMModel):
    id: int
    case_id: uuid.UUID
    mitre_id: str
    name: str
    tactic: str
    confidence: float
    evidence_summary: str
    linked_event_id: int | None
    created_at: datetime


# --- Timeline ---


class TimelineEventCreate(BaseModel):
    timestamp: datetime
    source: str = "manual"
    host: str = ""
    user: str = ""
    summary: str
    severity: str = "info"
    is_suspicious: bool = False


class TimelineEventOut(ORMModel):
    id: int
    case_id: uuid.UUID
    timestamp: datetime
    source: str
    host: str
    user: str
    summary: str
    severity: str
    is_suspicious: bool


# --- Audit / Summary ---


class AuditLogOut(ORMModel):
    id: int
    case_id: uuid.UUID
    actor: str
    action: str
    detail: str
    created_at: datetime


class PhaseProgress(BaseModel):
    phase: str
    total: int
    done: int
    percent: float


class ResponseSummary(BaseModel):
    case: CaseOut
    phase_progress: list[PhaseProgress]
    open_tasks: int
    completed_tasks: int
    ioc_counts: dict[str, int]
    technique_count: int
    next_actions: list[TaskOut]
    narrative: str
