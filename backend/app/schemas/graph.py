
import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel


class GraphEvent(BaseModel):
    id: uuid.UUID
    timestamp: datetime
    event_type: str
    source: str
    source_ip: str
    destination_ip: str
    details: dict[str, Any]


class GraphNode(BaseModel):
    id: uuid.UUID
    type: str
    name: str
    attributes: dict[str, Any]
    event_ids: list[uuid.UUID]


class GraphEdge(BaseModel):
    id: uuid.UUID
    source: uuid.UUID
    target: uuid.UUID
    relationship_type: str
    event_ids: list[uuid.UUID]


class GraphResponse(BaseModel):
    case_id: uuid.UUID
    nodes: list[GraphNode]
    edges: list[GraphEdge]
    events: list[GraphEvent]
