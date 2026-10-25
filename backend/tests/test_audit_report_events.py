import uuid
from types import SimpleNamespace

from app.api.v1 import audit as audit_api
from app.api.v1 import reports as reports_api


def test_report_generate_view_and_download_append_audit_rows(monkeypatch):
    case_id = uuid.uuid4()
    user = SimpleNamespace(id=uuid.uuid4())
    added = []
    commits = []

    class FakeDB:
        def add(self, row):
            added.append(row)

        def commit(self):
            commits.append(True)

    db = FakeDB()

    def make_entry(db_arg, user_arg, action, resource, request=None, case_id=None, details=None):
        entry = SimpleNamespace(action=action, resource=resource, case_id=case_id, details=details)
        db_arg.add(entry)
        return entry

    monkeypatch.setattr(reports_api, "log_audit_event", make_entry)
    for action in ("report.generated", "report.viewed", "report.downloaded"):
        reports_api._audit_report_action(db, user, case_id, action, report_id="report-id")

    assert [row.action for row in added] == ["report.generated", "report.viewed", "report.downloaded"]
    assert all(row.resource == "report:report-id" and row.case_id == case_id for row in added)
    assert len(commits) == len(added)


def test_audit_router_exposes_no_edit_or_delete_operations():
    assert {route.methods for route in audit_api.router.routes} == {{"GET"}}


def test_audit_response_field_names_match_frontend_contract():
    from app.schemas.audit import AuditLogResponse

    response = AuditLogResponse(
        id=uuid.uuid4(), user_id=uuid.uuid4(), case_id=None, action="report.viewed",
        resource="report:report-id", ip_address=None, user_agent=None, details={"report_id": "report-id"},
        timestamp="2026-10-25T00:00:00Z", user_name="examiner", user_role="investigator",
        target_type="report", target_id="report-id",
    )
    assert response.target_type == "report"
    assert response.target_id == "report-id"
    assert response.user_name == "examiner"
