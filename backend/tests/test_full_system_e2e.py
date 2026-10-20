import asyncio
from pathlib import Path
import httpx
from app.main import app
from app.db.init_db import init_db

async def run_e2e():
    init_db()

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        # 1. Health check
        res = await client.get("/health")
        assert res.status_code == 200
        assert res.json()["status"] == "ok"
        print("[1/13] Health check: OK")

        # 2. Login as admin
        login_res = await client.post(
            "/api/v1/auth/login",
            json={"email": "saremworkuu@gmail.com", "password": "Admin@2026!"}
        )
        assert login_res.status_code == 200, f"Login failed: {login_res.text}"
        login_data = login_res.json()
        token = login_data.get("token") or login_data.get("access_token")
        assert token, "Token missing in response"
        assert login_data["user"]["email"] == "saremworkuu@gmail.com"
        assert login_data["user"]["role"] == "admin"
        print("[2/13] Admin login: OK, token received")

        headers = {"Authorization": f"Bearer {token}"}

        # 3. Get /me
        me_res = await client.get("/api/v1/auth/me", headers=headers)
        assert me_res.status_code == 200
        assert me_res.json()["email"] == "saremworkuu@gmail.com"
        print("[3/13] Auth /me check: OK")

        # 4. List users
        users_res = await client.get("/api/v1/auth/users", headers=headers)
        assert users_res.status_code == 200
        assert len(users_res.json()) >= 2
        print(f"[4/13] List users: OK ({len(users_res.json())} users)")

        # 5. List cases
        cases_res = await client.get("/api/v1/cases/", headers=headers)
        assert cases_res.status_code == 200
        cases = cases_res.json()
        assert len(cases) >= 1
        print(f"[5/13] List cases: OK ({len(cases)} cases)")

        # 6. Create a new test case
        new_case_res = await client.post(
            "/api/v1/cases/",
            json={"name": "E2E Automated Case", "description": "Verification of complete backend flow"},
            headers=headers
        )
        assert new_case_res.status_code == 201
        created_case = new_case_res.json()
        test_case_id = created_case["id"]
        print(f"[6/13] Case creation: OK ({test_case_id})")

        # 7. Upload evidence file (auth.log from sample data)
        sample_file_path = Path(__file__).resolve().parents[2] / "sample-data" / "scenario-1" / "auth.log"
        if sample_file_path.exists():
            with open(sample_file_path, "rb") as f:
                upload_res = await client.post(
                    f"/api/v1/cases/{test_case_id}/evidence/upload",
                    files={"file": ("auth.log", f, "text/plain")},
                    data={"file_type": "auth_log", "description": "SSH Authentication logs"},
                    headers=headers
                )
            assert upload_res.status_code == 201, f"Upload failed: {upload_res.text}"
            ev_data = upload_res.json()
            assert ev_data["filename"] == "auth.log"
            evidence_id = ev_data["id"]
            print(f"[7/13] Evidence upload & parse: OK ({evidence_id}, {ev_data.get('event_count', 0)} events)")

            # 8. Verify events were created and queryable
            events_res = await client.get(f"/api/v1/cases/{test_case_id}/events", headers=headers)
            assert events_res.status_code == 200
            events_data = events_res.json()
            events = events_data if isinstance(events_data, list) else events_data.get("events", [])
            assert len(events) > 0, "Expected normalized events from auth.log"
            print(f"[8/13] Events retrieval: OK ({len(events)} events returned)")

            # 9. Verify timeline endpoint
            timeline_res = await client.get(f"/api/v1/cases/{test_case_id}/timeline", headers=headers)
            assert timeline_res.status_code == 200
            print("[9/13] Timeline retrieval: OK")

            # 10. Verify attack graph endpoint
            graph_res = await client.get(f"/api/v1/cases/{test_case_id}/graph", headers=headers)
            assert graph_res.status_code == 200
            graph_data = graph_res.json()
            assert "nodes" in graph_data and "edges" in graph_data
            print(f"[10/13] Attack graph generation: OK ({len(graph_data['nodes'])} nodes, {len(graph_data['edges'])} edges)")

            # 11. Verify detections endpoint
            detections_res = await client.get(f"/api/v1/cases/{test_case_id}/detections", headers=headers)
            assert detections_res.status_code == 200
            print("[11/13] Detections execution: OK")

            # 12. Verify report generation
            report_res = await client.post(f"/api/v1/cases/{test_case_id}/reports/generate", headers=headers)
            assert report_res.status_code == 200, f"Report error: {report_res.text}"
            report_data = report_res.json()
            assert "executive_summary" in report_data
            print("[12/13] Forensic report generation: OK")

            # 13. Verify audit log retrieval
            audit_res = await client.get("/api/v1/audit/logs", headers=headers)
            assert audit_res.status_code == 200
            print(f"[13/13] Audit logs retrieval: OK ({len(audit_res.json())} entries)")

            print(f"\nSUCCESS: ALL 13 E2E INTEGRATION CHECKS PASSED FOR CASE {test_case_id}!")

if __name__ == "__main__":
    asyncio.run(run_e2e())
