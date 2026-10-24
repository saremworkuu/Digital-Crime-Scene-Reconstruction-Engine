# Graph schemas
from typing import Optional, List, Any
from pydantic import BaseModel, Field


class GraphNode(BaseModel):
    id: str
    label: str
    type: str  # 'host' | 'user' | 'ip' | 'process' | 'domain' | 'file'
    is_compromised: bool = False
    is_attack_path: bool = False
    event_count: int = 1
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    details: Optional[Any] = None


class GraphEdge(BaseModel):
    id: str
    source: str
    target: str
    label: str
    count: int = 1
    is_attack_path: bool = False
    severity: str = "low"
    timestamp: Optional[str] = None
    protocol: Optional[str] = None


class AttackGraphData(BaseModel):
    nodes: List[GraphNode] = Field(default_factory=list)
    edges: List[GraphEdge] = Field(default_factory=list)
