"""
Pytest configuration and shared fixtures for backend tests.

Uses SQLite in-memory via aiosqlite for fast, isolated testing.
Overrides FastAPI dependencies so tests run without Postgres/Redis.
"""

import uuid
from pathlib import Path

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

# ── Override settings BEFORE importing the app ──────────────────────
import os

os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///:memory:")
os.environ.setdefault("SECRET_KEY", "test-secret-key")

from app.database import Base, get_db  # noqa: E402
from app.auth import get_current_analyst, create_access_token  # noqa: E402
from app.models.analyst import Analyst  # noqa: E402
# Import all models so Base.metadata knows every table
import app.models  # noqa: E402, F401

# ── Test DB engine ──────────────────────────────────────────────────

_engine = create_async_engine("sqlite+aiosqlite:///:memory:")
_session_factory = async_sessionmaker(
    _engine, class_=AsyncSession, expire_on_commit=False
)

TEST_ANALYST_ID = uuid.UUID("00000000-0000-4000-8000-000000000001")
OTHER_ANALYST_ID = uuid.UUID("00000000-0000-4000-8000-000000000002")


# ── Dependency overrides ────────────────────────────────────────────

async def _override_get_db():
    async with _session_factory() as session:
        yield session


async def _override_get_current_analyst() -> uuid.UUID:
    return TEST_ANALYST_ID


# ── Fixtures ────────────────────────────────────────────────────────

@pytest_asyncio.fixture(autouse=True)
async def setup_db():
    """Create all tables, seed a test analyst, and tear down after each test."""
    from app.main import app

    app.dependency_overrides[get_db] = _override_get_db
    app.dependency_overrides[get_current_analyst] = _override_get_current_analyst

    async with _engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    # Seed test analyst
    async with _session_factory() as session:
        analyst = Analyst(
            id=TEST_ANALYST_ID,
            email="analyst@test.local",
            hashed_password="not-a-real-hash",
            display_name="Test Analyst",
        )
        session.add(analyst)
        await session.commit()

    yield

    async with _engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)

    app.dependency_overrides.clear()


@pytest_asyncio.fixture
async def async_client():
    """Async HTTP client wired to the FastAPI test app."""
    from app.main import app

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        yield client


@pytest.fixture
def auth_headers() -> dict[str, str]:
    """Bearer-token headers for the default test analyst."""
    token = create_access_token(TEST_ANALYST_ID)
    return {"Authorization": f"Bearer {token}"}


def fixture_path(name: str) -> Path:
    """Resolve a synthetic .eml fixture by filename."""
    return Path(__file__).parent / "fixtures" / name
