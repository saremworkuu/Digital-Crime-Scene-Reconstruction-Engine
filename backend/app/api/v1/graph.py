
import ipaddress
import uuid

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.dependencies import get_current_user
from app.core.permissions import get_authorized_case
from app.db.models.entity import Entity
from app.db.models.events import Event
from app.db.models.relationship import Relationship
from app.db.models.user import User
from app.db.session import get_db
from app.schemas.graph import (
    GraphEdge,
    GraphEvent,
    GraphNode,
    GraphResponse,
)


router = APIRouter()

NETWORK_EVENT_TYPES = {
    "network_connection",
    "dns_query",
    "dns_request",
    "dns_response",
}


def normalize_ip(value):
    if not isinstance(value, str):
        return None

    try:
        return str(ipaddress.ip_address(value.strip()))
    except ValueError:
        return None


@router.get("/{case_id}", response_model=GraphResponse)
def get_attack_graph(
    case_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    get_authorized_case(
        case_id=case_id,
        current_user=current_user,
        db=db,
        allow_viewer=True,
    )

    entities = db.execute(
        select(Entity)
        .where(Entity.case_id == case_id)
        .order_by(Entity.name.asc())
    ).scalars().all()

    relationships = db.execute(
        select(Relationship)
        .where(Relationship.case_id == case_id)
        .order_by(Relationship.id.asc())
    ).scalars().all()

    stored_events = db.execute(
        select(Event)
        .where(Event.case_id == case_id)
        .order_by(Event.timestamp.asc(), Event.id.asc())
    ).scalars().all()

    nodes = [
        GraphNode(
            id=entity.id,
            type=entity.type,
            name=entity.name,
            attributes=entity.attributes or {},
            event_ids=[],
        )
        for entity in entities
    ]

    node_by_ip = {
        (node.type, node.name): node
        for node in nodes
    }

    edges = [
        GraphEdge(
            id=relationship.id,
            source=relationship.source_entity_id,
            target=relationship.target_entity_id,
            relationship_type=relationship.relationship_type,
            event_ids=[],
        )
        for relationship in relationships
    ]

    edge_by_key = {
        (edge.source, edge.target, edge.relationship_type): edge
        for edge in edges
    }

    graph_events = []

    for event in stored_events:
        event_type = event.event_type.lower()

        if event_type not in NETWORK_EVENT_TYPES:
            continue

        details = event.details or {}

        source_ip = normalize_ip(details.get("source_ip"))
        destination_ip = normalize_ip(details.get("destination_ip"))

        if not source_ip or not destination_ip:
            continue

        source_node = node_by_ip.get(("ip_address", source_ip))
        target_node = node_by_ip.get(("ip_address", destination_ip))

        if source_node is None or target_node is None:
            continue

        edge = edge_by_key.get(
            (source_node.id, target_node.id, event_type)
        )

        if edge is None:
            continue

        graph_event = GraphEvent(
            id=event.id,
            timestamp=event.timestamp,
            event_type=event_type,
            source=event.source,
            source_ip=source_ip,
            destination_ip=destination_ip,
            details=details,
        )

        graph_events.append(graph_event)
        edge.event_ids.append(event.id)
        source_node.event_ids.append(event.id)

        if target_node.id != source_node.id:
            target_node.event_ids.append(event.id)

    return GraphResponse(
        case_id=case_id,
        nodes=nodes,
        edges=edges,
        events=graph_events,
    )
