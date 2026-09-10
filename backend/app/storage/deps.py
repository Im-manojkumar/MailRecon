from functools import lru_cache

from app.config import settings
from app.storage.base import EvidenceStore
from app.storage.local import LocalEvidenceStore


@lru_cache
def _get_store_instance() -> EvidenceStore:
    return LocalEvidenceStore(settings.STORAGE_ROOT)


def get_evidence_store() -> EvidenceStore:
    """Dependency that provides the configured EvidenceStore instance."""
    return _get_store_instance()
