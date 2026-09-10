import pytest
from httpx import AsyncClient

@pytest.mark.asyncio
async def test_register_and_login(async_client: AsyncClient):
    from app.main import app
    from app.auth import get_current_analyst
    
    # Remove override just for this test
    override = app.dependency_overrides.pop(get_current_analyst, None)
    
    # Register
    reg_data = {"email": "new@example.com", "password": "password123", "display_name": "New User"}
    reg_res = await async_client.post("/api/auth/register", json=reg_data)
    assert reg_res.status_code == 201
    assert "access_token" in reg_res.json()
    
    # Login
    login_data = {"email": "new@example.com", "password": "password123"}
    login_res = await async_client.post("/api/auth/login", json=login_data)
    assert login_res.status_code == 200
    assert "access_token" in login_res.json()
    token = login_res.json()["access_token"]
    
    # Get Me
    me_res = await async_client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert me_res.status_code == 200
    assert me_res.json()["email"] == "new@example.com"
    
    # Wrong password
    bad_login = {"email": "new@example.com", "password": "wrong"}
    bad_res = await async_client.post("/api/auth/login", json=bad_login)
    assert bad_res.status_code == 401
    
    # Restore override
    if override:
        app.dependency_overrides[get_current_analyst] = override
