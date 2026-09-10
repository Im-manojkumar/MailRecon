import hashlib
import uuid
import pytest
from httpx import AsyncClient

from app.config import settings
from app.storage.deps import get_evidence_store
from tests.conftest import fixture_path, TEST_ANALYST_ID, OTHER_ANALYST_ID


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
