import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import uuid

from app.config import settings
from app.database import engine
from app.routers import auth, campaigns, cases, health

logger = logging.getLogger(__name__)

@asynccontextmanager
async def lifespan(app: FastAPI):
    # DB init or other startup tasks could go here
    logger.info("Starting up MailRecon AI backend")
    yield
    # Cleanup
    await engine.dispose()
    logger.info("Shutting down")

app = FastAPI(
    title="MailRecon AI",
    version="0.1.0",
    lifespan=lifespan
)

# CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.middleware("http")
async def add_request_id_middleware(request: Request, call_next):
    request_id = str(uuid.uuid4())
    request.state.request_id = request_id
    response = await call_next(request)
    response.headers["X-Request-ID"] = request_id
    return response

@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.error(f"Unhandled exception: {exc}")
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal server error"}
    )

app.include_router(health.router, prefix="/api", tags=["health"])
app.include_router(auth.router, prefix="/api/auth", tags=["auth"])
app.include_router(cases.router, prefix="/api/cases", tags=["cases"])
app.include_router(campaigns.router, prefix="/api/campaigns", tags=["campaigns"])
