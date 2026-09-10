import hashlib
import os
from pathlib import Path
import tempfile
from typing import AsyncIterator

from app.storage.base import EvidenceStore


class LocalEvidenceStore(EvidenceStore):
    def __init__(self, root_path: str):
        self.root = Path(root_path).resolve()
        self.root.mkdir(parents=True, exist_ok=True)

    def _get_path(self, key: str) -> Path:
        # Normalize key and reject absolute paths or traversal
        cleaned_key = key.replace("\\", "/").lstrip("/")
        if ".." in cleaned_key.split("/"):
            raise ValueError("Invalid storage key: path traversal detected")
        
        full_path = (self.root / cleaned_key).resolve()
        try:
            full_path.relative_to(self.root)
        except ValueError:
            raise ValueError("Invalid storage key: outside storage root")
            
        return full_path

    async def put(self, key: str, data: bytes) -> str:
        path = self._get_path(key)
        path.parent.mkdir(parents=True, exist_ok=True)

        # Atomic write via temp file in same directory
        temp_file = tempfile.NamedTemporaryFile(dir=path.parent, delete=False)
        temp_path = Path(temp_file.name)
        try:
            temp_file.write(data)
            temp_file.flush()
            temp_file.close()
            os.replace(temp_path, path)
        except Exception:
            if temp_path.exists():
                temp_path.unlink()
            raise

        return key

    async def get(self, key: str) -> bytes:
        path = self._get_path(key)
        if not path.exists():
            raise FileNotFoundError(f"Key '{key}' not found in evidence store")
        with open(path, "rb") as f:
            return f.read()

    async def exists(self, key: str) -> bool:
        try:
            path = self._get_path(key)
            return path.exists() and path.is_file()
        except ValueError:
            return False

    async def delete(self, key: str) -> None:
        path = self._get_path(key)
        if path.exists() and path.is_file():
            path.unlink()

    async def get_stream(self, key: str, chunk_size: int = 8192) -> AsyncIterator[bytes]:
        path = self._get_path(key)
        if not path.exists() or not path.is_file():
            raise FileNotFoundError(f"Key '{key}' not found in evidence store")

        with open(path, "rb") as f:
            while chunk := f.read(chunk_size):
                yield chunk

    async def verify_integrity(self, key: str, expected_sha256: str) -> bool:
        path = self._get_path(key)
        if not path.exists() or not path.is_file():
            return False

        hasher = hashlib.sha256()
        with open(path, "rb") as f:
            while chunk := f.read(65536):
                hasher.update(chunk)

        computed = hasher.hexdigest().lower()
        return computed == expected_sha256.strip().lower()
