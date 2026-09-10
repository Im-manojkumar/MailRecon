import os
from pathlib import Path
from typing import AsyncIterator
from app.storage.base import EvidenceStore

class LocalEvidenceStore(EvidenceStore):
    def __init__(self, root_path: str):
        self.root = Path(root_path).resolve()
        
    def _get_path(self, key: str) -> Path:
        # Prevent path traversal
        normalized_key = os.path.normpath(key).lstrip('/')
        full_path = (self.root / normalized_key).resolve()
        if not str(full_path).startswith(str(self.root)):
            raise ValueError("Invalid storage key (path traversal detected)")
        return full_path

    async def put(self, key: str, data: bytes) -> str:
        path = self._get_path(key)
        path.parent.mkdir(parents=True, exist_ok=True)
        # Using sync I/O for simplicity here, could use aiofiles
        with open(path, "wb") as f:
            f.write(data)
        return key

    async def get(self, key: str) -> bytes:
        path = self._get_path(key)
        if not path.exists():
            raise FileNotFoundError(f"Key {key} not found")
        with open(path, "rb") as f:
            return f.read()

    async def exists(self, key: str) -> bool:
        return self._get_path(key).exists()

    async def delete(self, key: str) -> None:
        path = self._get_path(key)
        if path.exists():
            path.unlink()

    async def get_stream(self, key: str, chunk_size: int = 8192) -> AsyncIterator[bytes]:
        path = self._get_path(key)
        if not path.exists():
            raise FileNotFoundError(f"Key {key} not found")
            
        def iterfile():
            with open(path, "rb") as f:
                while chunk := f.read(chunk_size):
                    yield chunk
                    
        for c in iterfile():
            yield c
