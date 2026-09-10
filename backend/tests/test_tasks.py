import hashlib
import uuid
import pytest
from sqlalchemy import select

from app.models.case import Case, CaseStatus
from app.storage.deps import get_evidence_store
from app.tasks.jobs import _async_process_case
from tests.conftest import TEST_ANALYST_ID, get_test_session_factory


@pytest.mark.asyncio
async def test_process_case_job_success():
    session_factory = get_test_session_factory()
    from app.main import app
    storage = app.dependency_overrides[get_evidence_store]()

    # Prepare evidence
    content = b"From: user@example.com\r\nSubject: Test\r\n\r\nValid email body."
    sha256_hash = hashlib.sha256(content).hexdigest()
    storage_key = f"cases/{sha256_hash}.eml"
    await storage.put(storage_key, content)

    # Insert case in DB
    case_id = uuid.uuid4()
    async with session_factory() as session:
        case = Case(
            id=case_id,
            original_sha256=sha256_hash,
            original_size=len(content),
            filename="valid.eml",
            storage_key=storage_key,
            analyst_id=TEST_ANALYST_ID,
            status=CaseStatus.pending,
        )
        session.add(case)
        await session.commit()

    # Monkeypatch async_session_maker in tasks.jobs to use test DB
    import app.tasks.jobs as jobs_module
    orig_factory = jobs_module.async_session_maker
    orig_store_getter = jobs_module.get_evidence_store
    jobs_module.async_session_maker = session_factory
    jobs_module.get_evidence_store = lambda: storage

    try:
        success = await _async_process_case(case_id)
        assert success is True

        async with session_factory() as session:
            res = await session.execute(select(Case).where(Case.id == case_id))
            updated_case = res.scalars().first()
            assert updated_case.status == CaseStatus.processing
    finally:
        jobs_module.async_session_maker = orig_factory
        jobs_module.get_evidence_store = orig_store_getter


@pytest.mark.asyncio
async def test_process_case_job_missing_evidence():
    session_factory = get_test_session_factory()
    from app.main import app
    storage = app.dependency_overrides[get_evidence_store]()

    case_id = uuid.uuid4()
    async with session_factory() as session:
        case = Case(
            id=case_id,
            original_sha256="0" * 64,
            original_size=100,
            filename="missing.eml",
            storage_key="cases/missing.eml",
            analyst_id=TEST_ANALYST_ID,
            status=CaseStatus.pending,
        )
        session.add(case)
        await session.commit()

    import app.tasks.jobs as jobs_module
    orig_factory = jobs_module.async_session_maker
    orig_store_getter = jobs_module.get_evidence_store
    jobs_module.async_session_maker = session_factory
    jobs_module.get_evidence_store = lambda: storage

    try:
        success = await _async_process_case(case_id)
        assert success is False

        async with session_factory() as session:
            res = await session.execute(select(Case).where(Case.id == case_id))
            updated_case = res.scalars().first()
            assert updated_case.status == CaseStatus.failed
            assert "missing" in updated_case.metadata_json["error"].lower()
    finally:
        jobs_module.async_session_maker = orig_factory
        jobs_module.get_evidence_store = orig_store_getter


@pytest.mark.asyncio
async def test_process_case_job_corrupt_evidence():
    session_factory = get_test_session_factory()
    from app.main import app
    storage = app.dependency_overrides[get_evidence_store]()

    # Store file with content A, but record SHA-256 for content B
    content = b"Corrupt file content"
    storage_key = "cases/corrupt.eml"
    await storage.put(storage_key, content)

    case_id = uuid.uuid4()
    async with session_factory() as session:
        case = Case(
            id=case_id,
            original_sha256="f" * 64,  # mismatched hash
            original_size=len(content),
            filename="corrupt.eml",
            storage_key=storage_key,
            analyst_id=TEST_ANALYST_ID,
            status=CaseStatus.pending,
        )
        session.add(case)
        await session.commit()

    import app.tasks.jobs as jobs_module
    orig_factory = jobs_module.async_session_maker
    orig_store_getter = jobs_module.get_evidence_store
    jobs_module.async_session_maker = session_factory
    jobs_module.get_evidence_store = lambda: storage

    try:
        success = await _async_process_case(case_id)
        assert success is False

        async with session_factory() as session:
            res = await session.execute(select(Case).where(Case.id == case_id))
            updated_case = res.scalars().first()
            assert updated_case.status == CaseStatus.failed
            assert "integrity" in updated_case.metadata_json["error"].lower()
    finally:
        jobs_module.async_session_maker = orig_factory
        jobs_module.get_evidence_store = orig_store_getter
