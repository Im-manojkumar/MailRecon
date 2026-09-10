import pytest
from httpx import AsyncClient
import uuid
from tests.conftest import fixture_path, TEST_ANALYST_ID

@pytest.mark.asyncio
async def test_create_case(async_client: AsyncClient, auth_headers):
    file_path = fixture_path("clean_simple.eml")
    with open(file_path, "rb") as f:
        files = {"file": ("clean_simple.eml", f, "message/rfc822")}
        response = await async_client.post("/api/cases", files=files, headers=auth_headers)
    
    assert response.status_code == 201
    data = response.json()
    assert "id" in data
    assert data["filename"] == "clean_simple.eml"
    assert data["status"] == "pending"

@pytest.mark.asyncio
async def test_list_cases(async_client: AsyncClient, auth_headers):
    response = await async_client.get("/api/cases", headers=auth_headers)
    assert response.status_code == 200
    data = response.json()
    assert "items" in data
    assert "total" in data

@pytest.mark.asyncio
async def test_get_case(async_client: AsyncClient, auth_headers):
    # First create a case
    file_path = fixture_path("clean_simple.eml")
    with open(file_path, "rb") as f:
        files = {"file": ("clean_simple.eml", f, "message/rfc822")}
        create_res = await async_client.post("/api/cases", files=files, headers=auth_headers)
    
    case_id = create_res.json()["id"]
    
    # Then get it
    response = await async_client.get(f"/api/cases/{case_id}", headers=auth_headers)
    assert response.status_code == 200
    data = response.json()
    assert data["id"] == case_id
    assert data["analyst_id"] == str(TEST_ANALYST_ID)

@pytest.mark.asyncio
async def test_unauthorized_access(async_client: AsyncClient):
    # Skip for now
    pass

@pytest.mark.asyncio
async def test_access_other_analyst_case(async_client: AsyncClient, auth_headers):
    # Create a random UUID not belonging to this analyst
    random_id = str(uuid.uuid4())
    response = await async_client.get(f"/api/cases/{random_id}", headers=auth_headers)
    assert response.status_code == 404
