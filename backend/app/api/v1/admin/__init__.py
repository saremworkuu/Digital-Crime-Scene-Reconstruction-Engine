from fastapi import APIRouter
from app.api.v1.admin import users, cases, evidence, rules, messages, audit, system

admin_router = APIRouter()

admin_router.include_router(users.router, prefix="/users", tags=["admin-users"])
admin_router.include_router(cases.router, prefix="/cases", tags=["admin-cases"])
admin_router.include_router(evidence.router, prefix="/evidence", tags=["admin-evidence"])
admin_router.include_router(rules.router, prefix="/rules", tags=["admin-rules"])
admin_router.include_router(messages.router, prefix="/messages", tags=["admin-messages"])
admin_router.include_router(audit.router, prefix="/audit", tags=["admin-audit"])
admin_router.include_router(system.router, prefix="/system", tags=["admin-system"])
