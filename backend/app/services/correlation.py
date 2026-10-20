# Correlation service

import ipaddress
import uuid

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.models.events import Event
from app.db.models.entity import Entity
from app.db.models.relationship import Relationship


NETWORK_EVENT_TYPES = {
    "network_connection",
    "dns_query",
    "dns_request",
    "dns_response",
}


def normalize_ip(value):
    """Return a normalized IP address, or None if invalid."""
    if not isinstance(value, str):
        return None

    try:
        return str(ipaddress.ip_address(value.strip()))
    except ValueError:
        return None


def correlate_case_events(db: Session, case_id: uuid.UUID) -> dict:
    """Create IP entities and observed network relationships for a case.

    The caller is responsible for committing the database transaction.
    """
    events = db.execute(
        select(Event)
        .where(Event.case_id == case_id)
        .order_by(Event.timestamp.asc(), Event.id.asc())
    ).scalars().all()

    # Cache existing entities so we reuse them.
    entities = db.execute(
        select(Entity).where(Entity.case_id == case_id)
    ).scalars().all()

    entity_cache = {
        (entity.type, entity.name): entity
        for entity in entities
    }

    # Cache existing relationships to make repeated runs idempotent.
    relationships = db.execute(
        select(Relationship).where(Relationship.case_id == case_id)
    ).scalars().all()

    relationship_cache = {
        (
            relationship.source_entity_id,
            relationship.target_entity_id,
            relationship.relationship_type,
        )
        for relationship in relationships
    }

    entities_created = 0
    relationships_created = 0

    def get_or_create_ip_entity(ip: str) -> Entity:
        nonlocal entities_created

        key = ("ip_address", ip)

        if key in entity_cache:
            return entity_cache[key]

        entity = Entity(
            case_id=case_id,
            type="ip_address",
            name=ip,
            attributes={"address": ip},
        )
        db.add(entity)
        db.flush()

        entity_cache[key] = entity
        entities_created += 1

        return entity

    for event in events:
        if event.event_type.lower() not in NETWORK_EVENT_TYPES:
            continue

        details = event.details or {}

        source_ip = normalize_ip(details.get("source_ip"))
        destination_ip = normalize_ip(details.get("destination_ip"))

        # Both endpoints must be valid IP addresses.
        if not source_ip or not destination_ip:
            continue

        if source_ip == destination_ip:
            continue

        source_entity = get_or_create_ip_entity(source_ip)
        target_entity = get_or_create_ip_entity(destination_ip)

        relationship_type = event.event_type.lower()

        relationship_key = (
            source_entity.id,
            target_entity.id,
            relationship_type,
        )

        if relationship_key in relationship_cache:
            continue

        relationship = Relationship(
            case_id=case_id,
            source_entity_id=source_entity.id,
            target_entity_id=target_entity.id,
            relationship_type=relationship_type,
        )
        db.add(relationship)
        db.flush()

        relationship_cache.add(relationship_key)
        relationships_created += 1

    return {
        "case_id": str(case_id),
        "events_examined": len(events),
        "entities_created": entities_created,
        "relationships_created": relationships_created,
    }
