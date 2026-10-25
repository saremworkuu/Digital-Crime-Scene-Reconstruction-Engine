from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

from app.api.v1.router import api_router
from app.core.rate_limit import limiter
from app.core.config import settings

app = FastAPI(
    title="Digital Crime Scene Reconstruction Engine API",
    version="1.0.0",
)

origins = [
    orig.strip()
    for orig in settings.CORS_ORIGINS.split(",")
    if orig.strip()
]
for default_origin in [
    "http://localhost:3000",
    "http://localhost:3001",
    "http://127.0.0.1:3000",
    "http://127.0.0.1:3001",
    "http://localhost:5173",
    "http://127.0.0.1:5173",
]:
    if default_origin not in origins:
        origins.append(default_origin)

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_origin_regex=r"^https?://(localhost|127\.0\.0\.1)(:\d+)?$",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["*"],
)

app.state.limiter = limiter
app.add_exception_handler(
    RateLimitExceeded,
    _rate_limit_exceeded_handler,
)

app.include_router(api_router, prefix="/api/v1")


from app.db.init_db import init_db
import shutil
from pathlib import Path


@app.on_event("startup")
def on_startup():
    init_db()
    try:
        root_dir = Path(__file__).resolve().parent.parent.parent
        src_dir = root_dir / "qa" / "artifacts"
        dst_dir = root_dir / "screenshots"
        if src_dir.exists():
            dst_dir.mkdir(exist_ok=True)
            for img_name in [
                "01_landing_page.png",
                "05_login_page.png",
                "07_investigator_dashboard.png",
                "08_cases_page.png",
                "10_evidence_vault.png",
                "11_timeline_visual.png",
                "13_attack_graph_2d.png",
                "15_attack_path.png",
                "16_findings_detections.png",
                "17_reports_page.png",
                "18_audit_trail.png",
                "23_admin_rules.png",
                "25_admin_system_health.png",
            ]:
                src_file = src_dir / img_name
                if src_file.exists():
                    shutil.copy2(src_file, dst_dir / img_name)
    except Exception:
        pass


@app.get("/health")
def health_check():
    return {"status": "ok", "service": "dcsre-backend"}

