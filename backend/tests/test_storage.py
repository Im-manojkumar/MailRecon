import hashlib
from pathlib import Path
import pytest

from app.storage.local import LocalEvidenceStore


@pytest.mark.asyncio
async def test_storage_put_get_exists_delete(tmp_path: Path):
    store = LocalEvidenceStore(str(tmp_path / "storage"))
    data = b"From: test@example.com\r\nSubject: Test\r\n\r\nHello Evidence Store"
    key = "cases/sample.eml"

    # Put
    res_key = await store.put(key, data)
    assert res_key == key

    # Exists
    assert await store.exists(key) is True
    assert await store.exists("cases/nonexistent.eml") is False

    # Get
    retrieved = await store.get(key)
    assert retrieved == data

    # Delete
    await store.delete(key)
    assert await store.exists(key) is False

    # Get after delete raises FileNotFoundError
    with pytest.raises(FileNotFoundError):
        await store.get(key)


@pytest.mark.asyncio
async def test_storage_streaming(tmp_path: Path):
    store = LocalEvidenceStore(str(tmp_path / "storage"))
    data = b"A" * 20000  # 20KB to test multi-chunk streaming
    key = "cases/large.eml"

    await store.put(key, data)

    chunks = []
    async for chunk in store.get_stream(key, chunk_size=4096):
        chunks.append(chunk)

    reconstructed = b"".join(chunks)
    assert reconstructed == data
    assert len(chunks) > 1


@pytest.mark.asyncio
async def test_storage_path_traversal_prevention(tmp_path: Path):
    store = LocalEvidenceStore(str(tmp_path / "storage"))
    data = b"malicious content"

    traversal_keys = [
        "../../etc/passwd",
        "../secret.txt",
        "cases/../../outside.txt",
        "subdir/../../../evil.eml",
    ]

    for bad_key in traversal_keys:
        with pytest.raises(ValueError, match="path traversal|outside storage root"):
            await store.put(bad_key, data)

        with pytest.raises(ValueError, match="path traversal|outside storage root"):
            await store.get(bad_key)


@pytest.mark.asyncio
async def test_storage_verify_integrity(tmp_path: Path):
    store = LocalEvidenceStore(str(tmp_path / "storage"))
    data = b"Original pristine email bytes"
    expected_hash = hashlib.sha256(data).hexdigest()
    key = "cases/integrity_test.eml"

    await store.put(key, data)

    # Valid integrity check
    assert await store.verify_integrity(key, expected_hash) is True
    assert await store.verify_integrity(key, expected_hash.upper()) is True  # case-insensitive

    # Tampered / mismatched hash
    tampered_hash = hashlib.sha256(b"Tampered bytes").hexdigest()
    assert await store.verify_integrity(key, tampered_hash) is False

    # Nonexistent key
    assert await store.verify_integrity("cases/not_here.eml", expected_hash) is False
