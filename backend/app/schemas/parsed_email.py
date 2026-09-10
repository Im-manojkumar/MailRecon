from datetime import datetime
from typing import Any, Dict, List, Optional
import uuid

from pydantic import BaseModel, ConfigDict


class AttachmentInfo(BaseModel):
    filename: str
    content_type: str
    size: int
    sha256: str
    is_macro: bool
    is_inline: bool
    content_id: Optional[str] = None
    storage_key: Optional[str] = None


class ExtractedUrl(BaseModel):
    url: str
    defanged: str
    domain: str
    is_ip: bool
    source: str
    anchor_text: Optional[str] = None
    occurrences: int = 1


class ReceivedHop(BaseModel):
    hop_number: int
    from_claimed: Optional[str] = None
    by_node: Optional[str] = None
    ip: Optional[str] = None
    protocol: Optional[str] = None
    is_tls: bool = False
    timestamp: Optional[str] = None
    raw: str


class ParsedEmailResponse(BaseModel):
    id: uuid.UUID
    case_id: uuid.UUID
    headers_json: Optional[Dict[str, Any]] = None
    body_text: Optional[str] = None
    body_html: Optional[str] = None
    attachments_json: Optional[List[Dict[str, Any]]] = None
    urls_json: Optional[List[Dict[str, Any]]] = None
    auth_results_json: Optional[Dict[str, Any]] = None
    received_chain_json: Optional[List[Dict[str, Any]]] = None
    parsed_at: datetime

    model_config = ConfigDict(from_attributes=True)
