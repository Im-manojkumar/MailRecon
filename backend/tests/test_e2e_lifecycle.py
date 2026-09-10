"""
End-to-end integration test validating the entire MailRecon AI lifecycle:
Upload -> Evidence Storage -> Worker Pipeline (Parsing, Detectors, 1D-CNN+Bi-GRU, AI, Scoring, Route, Graph) -> REST APIs -> Immutable Report Export.
"""
import hashlib
import json
import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

import app.tasks.jobs as jobs_module
from app.models.case import Case, CaseStatus
from app.models.indicator import Indicator
from app.storage.base import EvidenceStore
from app.storage.deps import get_evidence_store
from app.tasks.jobs import _async_process_case
from tests.conftest import fixture_path, get_test_session_factory, TEST_ANALYST_ID


@pytest.mark.asyncio
async def test_full_e2e_case_lifecycle(async_client: AsyncClient, auth_headers: dict):
    """
    Simulates a full security analyst investigation workflow from email upload to final report export.
    """
    session_factory = get_test_session_factory()
    from app.main import app
    storage: EvidenceStore = app.dependency_overrides[get_evidence_store]()

    # Monkeypatch session maker and storage getter for background worker in tests
    orig_factory = jobs_module.async_session_maker
    orig_store_getter = jobs_module.get_evidence_store
    jobs_module.async_session_maker = session_factory
    jobs_module.get_evidence_store = lambda: storage

    try:
        # 1. Ingestion: Upload a malicious BEC fixture
        eml_file = fixture_path("bec_urgent.eml")
        eml_bytes = eml_file.read_bytes()
        expected_sha = hashlib.sha256(eml_bytes).hexdigest()

        files = {"file": ("bec_urgent.eml", eml_bytes, "message/rfc822")}
        res_upload = await async_client.post("/api/cases", files=files, headers=auth_headers)
        assert res_upload.status_code == 201
        case_data = res_upload.json()
        case_id = uuid.UUID(case_data["id"])
        assert case_data["original_sha256"] == expected_sha
        assert case_data["status"] == "pending"

        # 2. Worker Execution: Process the case through all analytical engines
        processed = await _async_process_case(case_id)
        assert processed is True

        # 3. Verify Case Detail API
        res_case = await async_client.get(f"/api/cases/{case_id}", headers=auth_headers)
        assert res_case.status_code == 200
        detail = res_case.json()
        assert detail["status"] == "completed"
        assert detail["metadata_json"] is not None

        # 4. Verify Parsed Structure API
        res_parsed = await async_client.get(f"/api/cases/{case_id}/parsed", headers=auth_headers)
        assert res_parsed.status_code == 200
        parsed_data = res_parsed.json()
        assert "headers_json" in parsed_data
        assert parsed_data["body_text"] is not None
        assert "wire" in parsed_data["body_text"].lower() or "transfer" in parsed_data["body_text"].lower()

        # 5. Verify Threat Findings API (Deterministic Rules + 1D-CNN + Bi-GRU)
        res_findings = await async_client.get(f"/api/cases/{case_id}/findings", headers=auth_headers)
        assert res_findings.status_code == 200
        findings_data = res_findings.json()
        f_items = findings_data["items"]
        assert len(f_items) > 0

        detectors_fired = {f["detector"] for f in f_items}
        # Either identity spoofing, bec_intent, or neural sequence detector fired
        assert any(d in detectors_fired for d in ["identity_spoofing", "bec_intent", "neural_sequence_detector"])

        # 6. Verify Truthful Heuristic Risk Score API
        res_score = await async_client.get(f"/api/cases/{case_id}/score", headers=auth_headers)
        assert res_score.status_code == 200
        score_data = res_score.json()
        assert score_data["is_heuristic"] is True
        assert score_data["score"] > 40.0
        assert score_data["coverage"] > 0.0
        assert score_data["confidence"] > 0.0
        assert score_data["uncertainty_label"] in ["definitive", "probable", "inconclusive"]

        # 7. Verify Grounded AI Forensic Briefing API
        res_ai = await async_client.get(f"/api/cases/{case_id}/ai-analysis", headers=auth_headers)
        assert res_ai.status_code == 200
        ai_data = res_ai.json()
        assert ai_data["is_grounded"] is True
        assert len(ai_data["executive_summary"]) > 20
        assert len(ai_data["recommended_actions"]) > 0

        # 8. Verify Route Analysis API
        res_route = await async_client.get(f"/api/cases/{case_id}/route", headers=auth_headers)
        assert res_route.status_code == 200
        route_data = res_route.json()
        assert "hops" in route_data

        # 9. Verify Indicator Graph API
        res_graph = await async_client.get(f"/api/cases/{case_id}/graph", headers=auth_headers)
        assert res_graph.status_code == 200
        graph_data = res_graph.json()
        assert len(graph_data["nodes"]) >= 2
        assert any(n["kind"] == "case" for n in graph_data["nodes"])
        assert any(n["kind"] == "email" for n in graph_data["nodes"])

        # 10. Verify Indicator DB Persistence API
        res_inds = await async_client.get(f"/api/cases/{case_id}/indicators", headers=auth_headers)
        assert res_inds.status_code == 200
        inds_data = res_inds.json()
        assert inds_data["total"] > 0

        # 11. Generate Immutable Forensic Reports (HTML & JSON)
        res_gen_html = await async_client.post(f"/api/cases/{case_id}/report?format=html", headers=auth_headers)
        assert res_gen_html.status_code == 201
        html_rep = res_gen_html.json()
        assert html_rep["format"] == "html"
        assert len(html_rep["integrity_sha256"]) == 64

        res_gen_json = await async_client.post(f"/api/cases/{case_id}/report?format=json", headers=auth_headers)
        assert res_gen_json.status_code == 201
        json_rep = res_gen_json.json()
        assert json_rep["format"] == "json"
        assert len(json_rep["integrity_sha256"]) == 64

        # 12. Download Reports & Verify Cryptographic Integrity
        res_dl_html = await async_client.get(f"/api/cases/{case_id}/reports/{html_rep['id']}", headers=auth_headers)
        assert res_dl_html.status_code == 200
        assert hashlib.sha256(res_dl_html.content).hexdigest() == html_rep["integrity_sha256"]

        res_dl_json = await async_client.get(f"/api/cases/{case_id}/reports/{json_rep['id']}", headers=auth_headers)
        assert res_dl_json.status_code == 200
        assert hashlib.sha256(res_dl_json.content).hexdigest() == json_rep["integrity_sha256"]

        # 13. Download Original .eml with Runtime Tamper Protection
        res_dl_orig = await async_client.get(f"/api/cases/{case_id}/original", headers=auth_headers)
        assert res_dl_orig.status_code == 200
        assert hashlib.sha256(res_dl_orig.content).hexdigest() == expected_sha

    finally:
        jobs_module.async_session_maker = orig_factory
        jobs_module.get_evidence_store = orig_store_getter
