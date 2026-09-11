import pytest
import uuid
from httpx import AsyncClient

from tests.conftest import fixture_path, TEST_ANALYST_ID


@pytest.mark.asyncio
async def test_list_campaigns_endpoint(async_client: AsyncClient, auth_headers):
    res = await async_client.get("/api/campaigns", headers=auth_headers)
    assert res.status_code == 200
    data = res.json()
    assert "items" in data
    assert "total" in data
    assert isinstance(data["items"], list)


@pytest.mark.asyncio
async def test_case_campaign_affiliation_endpoint(async_client: AsyncClient, auth_headers):
    # Upload a case
    file_path = fixture_path("clean_simple.eml")
    files = {"file": ("clean_simple.eml", file_path.read_bytes(), "message/rfc822")}
    create_res = await async_client.post("/api/cases", files=files, headers=auth_headers)
    case_id = create_res.json()["id"]

    # Check affiliation
    aff_res = await async_client.get(f"/api/cases/{case_id}/campaign", headers=auth_headers)
    assert aff_res.status_code == 200
    aff_data = aff_res.json()
    assert aff_data["case_id"] == case_id
    assert "is_part_of_campaign" in aff_data


@pytest.mark.asyncio
async def test_campaign_detail_404(async_client: AsyncClient, auth_headers):
    res = await async_client.get("/api/campaigns/CMP-NONEXISTENT", headers=auth_headers)
    assert res.status_code == 404
