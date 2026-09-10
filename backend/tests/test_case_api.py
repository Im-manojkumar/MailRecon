import hashlib
import uuid
import pytest
from httpx import AsyncClient

from app.config import settings
from app.storage.deps import get_evidence_store
from app.tasks.jobs import _async_process_case
import app.tasks.jobs as jobs_module
from tests.conftest import fixture_path, TEST_ANALYST_ID, OTHER_ANALYST_ID, get_test_session_factory


@pytest.mark.asyncio
async def test_create_case_success(async_client: AsyncClient, auth_headers):
    file_path = fixture_path("clean_simple.eml")
    content = file_path.read_bytes()
    expected_sha256 = hashlib.sha256(content).hexdigest()

    files = {"file": ("clean_simple.eml", content, "message/rfc822")}
    response = await async_client.post("/api/cases", files=files, headers=auth_headers)

    assert response.status_code == 201
    data = response.json()
    assert "id" in data
    assert data["filename"] == "clean_simple.eml"
    assert data["status"] == "pending"
    assert data["original_sha256"] == expected_sha256
    assert data["original_size"] == len(content)


@pytest.mark.asyncio
async def test_create_case_rejects_non_eml(async_client: AsyncClient, auth_headers):
    content = b"Not an eml file"
    files = {"file": ("malware.exe", content, "application/octet-stream")}
    response = await async_client.post("/api/cases", files=files, headers=auth_headers)

    assert response.status_code == 400
    assert "Only .eml files are accepted" in response.json()["detail"]


@pytest.mark.asyncio
async def test_create_case_rejects_oversized_file(async_client: AsyncClient, auth_headers, monkeypatch):
    monkeypatch.setattr(settings, "MAX_UPLOAD_BYTES", 50)
    oversized_content = b"X" * 100
    files = {"file": ("oversized.eml", oversized_content, "message/rfc822")}
    response = await async_client.post("/api/cases", files=files, headers=auth_headers)

    assert response.status_code == 413
    assert "exceeds maximum allowed size" in response.json()["detail"]


@pytest.mark.asyncio
async def test_list_cases(async_client: AsyncClient, auth_headers):
    response = await async_client.get("/api/cases", headers=auth_headers)
    assert response.status_code == 200
    data = response.json()
    assert "items" in data
    assert "total" in data


@pytest.mark.asyncio
async def test_get_case(async_client: AsyncClient, auth_headers):
    file_path = fixture_path("clean_simple.eml")
    files = {"file": ("clean_simple.eml", file_path.read_bytes(), "message/rfc822")}
    create_res = await async_client.post("/api/cases", files=files, headers=auth_headers)
    case_id = create_res.json()["id"]

    response = await async_client.get(f"/api/cases/{case_id}", headers=auth_headers)
    assert response.status_code == 200
    data = response.json()
    assert data["id"] == case_id
    assert data["analyst_id"] == str(TEST_ANALYST_ID)


@pytest.mark.asyncio
async def test_download_original_file_success(async_client: AsyncClient, auth_headers):
    file_path = fixture_path("clean_simple.eml")
    original_bytes = file_path.read_bytes()
    expected_sha256 = hashlib.sha256(original_bytes).hexdigest()

    files = {"file": ("clean_simple.eml", original_bytes, "message/rfc822")}
    create_res = await async_client.post("/api/cases", files=files, headers=auth_headers)
    case_id = create_res.json()["id"]

    download_res = await async_client.get(f"/api/cases/{case_id}/original", headers=auth_headers)
    assert download_res.status_code == 200
    assert download_res.content == original_bytes
    assert download_res.headers["X-Evidence-SHA256"] == expected_sha256
    assert "clean_simple.eml" in download_res.headers["Content-Disposition"]


@pytest.mark.asyncio
async def test_download_original_file_tamper_detection(async_client: AsyncClient, auth_headers):
    """Verify that any modification to evidence on disk triggers 409 tamper detection."""
    from app.main import app

    file_path = fixture_path("clean_simple.eml")
    original_bytes = file_path.read_bytes()

    files = {"file": ("clean_simple.eml", original_bytes, "message/rfc822")}
    create_res = await async_client.post("/api/cases", files=files, headers=auth_headers)
    case_id = create_res.json()["id"]

    # Access current evidence store from dependency override
    store_factory = app.dependency_overrides.get(get_evidence_store)
    store = store_factory()

    # Simulate malicious modification or disk bitrot
    sha256_hash = hashlib.sha256(original_bytes).hexdigest()
    storage_key = f"cases/{sha256_hash}.eml"
    await store.put(storage_key, b"TAMPERED CONTENT: Injected phishing payload")

    # Attempt to download the altered evidence
    download_res = await async_client.get(f"/api/cases/{case_id}/original", headers=auth_headers)
    assert download_res.status_code == 409
    assert "Evidence integrity violation" in download_res.json()["detail"]


@pytest.mark.asyncio
async def test_unauthorized_access(async_client: AsyncClient):
    from app.main import app
    from app.auth import get_current_analyst

    # Temporarily remove dependency override to test real unauthenticated rejection
    override = app.dependency_overrides.pop(get_current_analyst, None)
    try:
        response = await async_client.get("/api/cases")
        assert response.status_code == 401
    finally:
        if override:
            app.dependency_overrides[get_current_analyst] = override


@pytest.mark.asyncio
async def test_access_other_analyst_case(async_client: AsyncClient, auth_headers):
    random_id = str(uuid.uuid4())
    response = await async_client.get(f"/api/cases/{random_id}", headers=auth_headers)
    assert response.status_code == 404


@pytest.mark.asyncio
async def test_get_parsed_email_lifecycle(async_client: AsyncClient, auth_headers):
    """Test parsed endpoint returns 404 before processing, and 200 with full data after processing."""
    from app.main import app
    session_factory = get_test_session_factory()
    store = app.dependency_overrides[get_evidence_store]()

    # 1. Upload case
    file_path = fixture_path("clean_simple.eml")
    files = {"file": ("clean_simple.eml", file_path.read_bytes(), "message/rfc822")}
    create_res = await async_client.post("/api/cases", files=files, headers=auth_headers)
    case_id = create_res.json()["id"]

    # 2. Before parsing, should return 404
    parsed_res = await async_client.get(f"/api/cases/{case_id}/parsed", headers=auth_headers)
    assert parsed_res.status_code == 404

    # 3. Execute worker processing job
    orig_factory = jobs_module.async_session_maker
    orig_store_getter = jobs_module.get_evidence_store
    jobs_module.async_session_maker = session_factory
    jobs_module.get_evidence_store = lambda: store

    try:
        success = await _async_process_case(uuid.UUID(case_id))
        assert success is True
    finally:
        jobs_module.async_session_maker = orig_factory
        jobs_module.get_evidence_store = orig_store_getter

    # 4. After parsing, should return 200 with complete parse details
    parsed_res = await async_client.get(f"/api/cases/{case_id}/parsed", headers=auth_headers)
    assert parsed_res.status_code == 200
    data = parsed_res.json()
    assert data["case_id"] == case_id
    assert "Meeting Tomorrow" in data["headers_json"]["subject"]
    assert "Are we still on for the meeting tomorrow?" in data["body_text"]
    assert data["auth_results_json"]["spf"]["result"] == "pass"
    assert len(data["received_chain_json"]) >= 1


@pytest.mark.asyncio
async def test_attachment_download_lifecycle(async_client: AsyncClient, auth_headers):
    """Test that attachments parsed from an email can be safely downloaded by hash."""
    from app.main import app
    session_factory = get_test_session_factory()
    store = app.dependency_overrides[get_evidence_store]()

    # 1. Upload email with macro attachment
    file_path = fixture_path("attachment_macro.eml")
    files = {"file": ("attachment_macro.eml", file_path.read_bytes(), "message/rfc822")}
    create_res = await async_client.post("/api/cases", files=files, headers=auth_headers)
    case_id = create_res.json()["id"]

    # 2. Process case
    orig_factory = jobs_module.async_session_maker
    orig_store_getter = jobs_module.get_evidence_store
    jobs_module.async_session_maker = session_factory
    jobs_module.get_evidence_store = lambda: store

    try:
        await _async_process_case(uuid.UUID(case_id))
    finally:
        jobs_module.async_session_maker = orig_factory
        jobs_module.get_evidence_store = orig_store_getter

    # 3. Retrieve parsed attachments
    parsed_res = await async_client.get(f"/api/cases/{case_id}/parsed", headers=auth_headers)
    attachments = parsed_res.json()["attachments_json"]
    assert len(attachments) == 1
    att = attachments[0]
    att_sha256 = att["sha256"]

    # 4. Download attachment
    att_res = await async_client.get(f"/api/cases/{case_id}/attachments/{att_sha256}", headers=auth_headers)
    assert att_res.status_code == 200
    assert att_res.headers["content-type"] == "application/octet-stream"
    assert "invoice_2024.xlsm" in att_res.headers["content-disposition"]
    assert att_res.headers["x-attachment-sha256"] == att_sha256

    # 5. Nonexistent attachment returns 404
    bad_res = await async_client.get(f"/api/cases/{case_id}/attachments/badhash", headers=auth_headers)
    assert bad_res.status_code == 404


@pytest.mark.asyncio
async def test_get_findings_lifecycle(async_client: AsyncClient, auth_headers):
    """Test that findings are generated during processing and queryable via the API."""
    from app.main import app
    session_factory = get_test_session_factory()
    store = app.dependency_overrides[get_evidence_store]()

    # 1. Upload BEC case
    file_path = fixture_path("bec_urgent.eml")
    files = {"file": ("bec_urgent.eml", file_path.read_bytes(), "message/rfc822")}
    create_res = await async_client.post("/api/cases", files=files, headers=auth_headers)
    case_id = create_res.json()["id"]

    # 2. Before processing, findings are empty
    pre_res = await async_client.get(f"/api/cases/{case_id}/findings", headers=auth_headers)
    assert pre_res.status_code == 200
    assert pre_res.json()["total"] == 0

    # 3. Process case
    orig_factory = jobs_module.async_session_maker
    orig_store_getter = jobs_module.get_evidence_store
    jobs_module.async_session_maker = session_factory
    jobs_module.get_evidence_store = lambda: store

    try:
        await _async_process_case(uuid.UUID(case_id))
    finally:
        jobs_module.async_session_maker = orig_factory
        jobs_module.get_evidence_store = orig_store_getter

    # 4. After processing, findings are populated
    findings_res = await async_client.get(f"/api/cases/{case_id}/findings", headers=auth_headers)
    assert findings_res.status_code == 200
    data = findings_res.json()
    assert data["total"] >= 2
    detectors = [item["detector"] for item in data["items"]]
    assert "identity_spoofing" in detectors
    assert "bec_intent" in detectors
    assert all(item["case_id"] == case_id for item in data["items"])

