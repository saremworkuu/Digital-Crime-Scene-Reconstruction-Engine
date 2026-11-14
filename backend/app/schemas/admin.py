from typing import List, Optional, Any, Dict
from pydantic import BaseModel, EmailStr, Field


# ---------------------------------------------------------------------------
# USERS
# ---------------------------------------------------------------------------
class AdminUserSession(BaseModel):
    id: str
    device: str
    ip: str
    last_active: str


class AdminUserResponse(BaseModel):
    id: str
    name: str
    email: str
    role: str
    status: str
    last_login: str
    department: str
    created_at: str
    two_factor_enabled: bool
    failed_login_attempts: int
    sessions: List[AdminUserSession] = []


class AdminUserCreateRequest(BaseModel):
    name: str = Field(..., min_length=2, max_length=100)
    email: EmailStr
    role: str = Field("investigator")
    department: str = Field("Digital Forensics")
    status: Optional[str] = "active"
    password: Optional[str] = None


class AdminUserUpdateRequest(BaseModel):
    name: Optional[str] = None
    email: Optional[EmailStr] = None
    role: Optional[str] = None
    department: Optional[str] = None
    status: Optional[str] = None
    two_factor_enabled: Optional[bool] = None


# ---------------------------------------------------------------------------
# CASES
# ---------------------------------------------------------------------------
class AdminCaseResponse(BaseModel):
    id: str
    title: str
    status: str
    owner: str
    created_date: str
    assigned_investigators: List[str] = []
    is_archived: bool
    legal_hold: bool
    evidence_count: int
    description: str


class AdminCaseStatusUpdateRequest(BaseModel):
    status: str


class AdminCaseAssignRequest(BaseModel):
    investigators: List[str]


class AdminCaseLegalHoldRequest(BaseModel):
    legal_hold: bool
    reason: Optional[str] = None


class AdminCaseArchiveRequest(BaseModel):
    is_archived: bool


# ---------------------------------------------------------------------------
# EVIDENCE
# ---------------------------------------------------------------------------
class AdminEvidenceResponse(BaseModel):
    id: str
    case_id: str
    file_name: str
    type: str
    size_bytes: int
    uploader: str
    uploaded_at: str
    sha256: str
    expected_sha256: str
    parsing_status: str
    error_text: Optional[str] = None
    verified: Optional[bool] = None


class AdminEvidenceVerifyResponse(BaseModel):
    verified: bool
    computed_sha256: str
    expected_sha256: str
    match: bool


# ---------------------------------------------------------------------------
# SIGMA RULES
# ---------------------------------------------------------------------------
class AdminSigmaRuleResponse(BaseModel):
    id: str
    name: str
    severity: str
    mitre_id: str
    enabled: bool
    times_triggered: int
    description: str
    query: str
    created_at: str


class AdminSigmaRuleCreateRequest(BaseModel):
    name: str = Field(..., min_length=3)
    severity: str = Field("medium")
    mitre_id: str = Field(..., min_length=2)
    description: str = ""
    query: str = ""


class AdminSigmaRuleUpdateRequest(BaseModel):
    name: Optional[str] = None
    severity: Optional[str] = None
    mitre_id: Optional[str] = None
    description: Optional[str] = None
    query: Optional[str] = None
    enabled: Optional[bool] = None


class AdminSigmaRuleToggleRequest(BaseModel):
    enabled: bool


class AdminRuleTestResponse(BaseModel):
    ruleId: str
    matchCount: int
    sampleMatches: List[Dict[str, Any]]


# ---------------------------------------------------------------------------
# CONTACT MESSAGES
# ---------------------------------------------------------------------------
class AdminReplyMessage(BaseModel):
    id: str
    author: str
    role: str
    message: str
    timestamp: str


class AdminContactMessageResponse(BaseModel):
    id: str
    reference: str
    sender_name: str
    sender_email: str
    sender_phone: str
    subject: str
    category: str
    status: str
    priority: str
    assignee: Optional[str] = None
    date: str
    is_read: bool
    body: str
    reply_thread: List[AdminReplyMessage] = []


class AdminMessageReplyRequest(BaseModel):
    message: str = Field(..., min_length=1)
    author: Optional[str] = "Sarem Worku (Admin)"


class AdminMessageStatusRequest(BaseModel):
    status: str


class AdminMessagePriorityRequest(BaseModel):
    priority: str


class AdminMessageAssignRequest(BaseModel):
    assignee: Optional[str] = None


# ---------------------------------------------------------------------------
# AUDIT LOG
# ---------------------------------------------------------------------------
class AdminAuditEntryResponse(BaseModel):
    id: str
    timestamp: str
    user_id: str
    user_name: str
    role: str
    action: str
    case_id: Optional[str] = None
    target_type: str
    target_id: str
    details: Dict[str, Any] = {}
    ip_address: str


class AdminAuditCreateRequest(BaseModel):
    action: str
    target_type: str
    target_id: str
    case_id: Optional[str] = None
    details: Optional[Dict[str, Any]] = None


# ---------------------------------------------------------------------------
# SYSTEM HEALTH & SETTINGS
# ---------------------------------------------------------------------------
class AdminParserStatus(BaseModel):
    type: str
    status: str
    success_rate: str
    avg_latency: str
    files_processed: int


class AdminQueueJob(BaseModel):
    id: str
    file_name: str
    parser_type: str
    status: str
    started_at: str
    error: Optional[str] = None


class AdminSystemHealthResponse(BaseModel):
    parsers: List[AdminParserStatus]
    queue: List[AdminQueueJob]
    storage_used_bytes: int
    storage_total_bytes: int
    failed_logins_24h: int
    recent_errors: List[Dict[str, Any]]


class AdminSettingsResponse(BaseModel):
    time_zone: str
    org_name: str
    retention_days: int
    min_password_length: int
    two_factor_enforced: bool
    failed_login_lockout_limit: int


class AdminSettingsUpdateRequest(BaseModel):
    time_zone: Optional[str] = None
    org_name: Optional[str] = None
    retention_days: Optional[int] = None
    min_password_length: Optional[int] = None
    two_factor_enforced: Optional[bool] = None
    failed_login_lockout_limit: Optional[int] = None
