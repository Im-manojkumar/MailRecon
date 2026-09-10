from abc import ABC, abstractmethod
from typing import AsyncIterator

class EvidenceStore(ABC):
    @abstractmethod
    async def put(self, key: str, data: bytes) -> str:
        pass

    @abstractmethod
    async def get(self, key: str) -> bytes:
        pass

    @abstractmethod
    async def exists(self, key: str) -> bool:
        pass

    @abstractmethod
    async def delete(self, key: str) -> None:
        pass

    @abstractmethod
    async def get_stream(self, key: str) -> AsyncIterator[bytes]:
        pass
