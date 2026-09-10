from abc import ABC, abstractmethod
from typing import AsyncIterator


class EvidenceStore(ABC):
    @abstractmethod
    async def put(self, key: str, data: bytes) -> str:
        """Store raw bytes at key. Returns storage key."""
        pass

    @abstractmethod
    async def get(self, key: str) -> bytes:
        """Retrieve raw bytes for key."""
        pass

    @abstractmethod
    async def exists(self, key: str) -> bool:
        """Check if key exists in store."""
        pass

    @abstractmethod
    async def delete(self, key: str) -> None:
        """Delete key from store."""
        pass

    @abstractmethod
    async def get_stream(self, key: str, chunk_size: int = 8192) -> AsyncIterator[bytes]:
        """Stream raw bytes for key in chunks."""
        pass

    @abstractmethod
    async def verify_integrity(self, key: str, expected_sha256: str) -> bool:
        """Verify stored data matches expected SHA-256 hash."""
        pass
