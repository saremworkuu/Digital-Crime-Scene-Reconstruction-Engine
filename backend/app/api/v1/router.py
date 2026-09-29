from fastapi import APIRouter
from app.api.v1 import auth, users, cases, evidence, events, timeline, graph, detections, reports, audit

api_router = APIRouter()
api_router.include_router(auth.router, prefix="/auth", tags=["auth"])
api_router.include_router(users.router, prefix="/users", tags=["users"])
api_router.include_router(cases.router, prefix="/cases", tags=["cases"])
api_router.include_router(evidence.router, prefix="/evidence", tags=["evidence"])
api_router.include_router(events.router, prefix="/events", tags=["events"])
api_router.include_router(timeline.router, prefix="/timeline", tags=["timeline"])
api_router.include_router(graph.router, prefix="/graph", tags=["graph"])
api_router.include_router(detections.router, prefix="/detections", tags=["detections"])
api_router.include_router(reports.router, prefix="/reports", tags=["reports"])
api_router.include_router(audit.router, prefix="/audit", tags=["audit"])
