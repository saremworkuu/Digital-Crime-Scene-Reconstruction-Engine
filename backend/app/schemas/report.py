# Report schemas
from typing import Optional, List, Any, Dict
from pydantic import BaseModel, Field


class ForensicReportResponse(BaseModel):
    id: str
    case_id: str
    case_name: str
    generated_at: str
    generator_name: Optional[str] = "Lead Forensics Investigator"
    generator_role: Optional[str] = "investigator"
    version: str = "1.0"
    classification: str = "CONFIDENTIAL // TLP:AMBER - DFIR EVIDENTIARY"
    executive_summary: str
    evidence_inventory: List[Dict[str, Any]] = Field(default_factory=list)
    mitre_coverage: List[Dict[str, Any]] = Field(default_factory=list)
    attack_timeline_summary: List[Dict[str, Any]] = Field(default_factory=list)
    compromised_assets: Dict[str, Any] = Field(default_factory=dict)
    recommendations: List[str] = Field(default_factory=list)


class ReportSummaryItem(BaseModel):
    id: str
    case_id: str
    title: str
    version: str
    generator_name: Optional[str] = None
    generated_at: str

