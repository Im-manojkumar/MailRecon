"""Application settings via Pydantic."""

from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    # Database
    DATABASE_URL: str = "postgresql+asyncpg://mailrecon:mailrecon@postgres:5432/mailrecon"
    # Redis
    REDIS_URL: str = "redis://redis:6379/0"
    # Evidence storage
    STORAGE_ROOT: str = "./data/evidence"
    # Auth
    SECRET_KEY: str = Field(
        default="dev-secret-key-change-in-production",
        description="Secret key for JWT signing. MUST be changed in production.",
    )
    JWT_ALGORITHM: str = "HS256"
    JWT_EXPIRY_HOURS: int = 24
    # Limits
    MAX_UPLOAD_BYTES: int = 26_214_400  # 25 MB
    MAX_MIME_DEPTH: int = 10
    MAX_IMAGE_DECODE_BYTES: int = 10_485_760  # 10 MB
    # CORS
    CORS_ORIGINS: list[str] = [
        "http://localhost:3000",
        "http://localhost:3001",
        "http://localhost:3002",
        "http://localhost:3003",
        "http://localhost:3005",
        "http://127.0.0.1:3000",
        "http://127.0.0.1:3001",
        "http://127.0.0.1:3002",
        "http://127.0.0.1:3003",
        "http://127.0.0.1:3005",
    ]
    # AI
    AI_PROVIDER: str = "mock"  # "mock" | "gemini"
    GEMINI_API_KEY: str | None = None
    GEMINI_MODEL: str = "gemini-1.5-flash"

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )


@lru_cache
def get_settings() -> Settings:
    return Settings()


# Convenience alias — most modules import this directly.
settings = get_settings()
