"""
Database engine and session configuration.

Uses SQLAlchemy 2.0 async patterns. Types are chosen for
cross-database compatibility (PostgreSQL in production, SQLite in tests).
"""

from typing import AsyncGenerator

from sqlalchemy import JSON
from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase
from sqlalchemy import Uuid

from app.config import get_settings


def _build_engine():
    settings = get_settings()
    url = settings.DATABASE_URL
    # SQLite doesn't support pool_size / max_overflow
    kwargs: dict = {"pool_pre_ping": True}
    if "sqlite" not in url:
        kwargs.update(pool_size=10, max_overflow=20)
    return create_async_engine(url, **kwargs)


engine = _build_engine()

async_session_maker = async_sessionmaker(
    engine, class_=AsyncSession, expire_on_commit=False
)


class Base(DeclarativeBase):
    """Declarative base for all models."""
    pass


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    async with async_session_maker() as session:
        yield session
