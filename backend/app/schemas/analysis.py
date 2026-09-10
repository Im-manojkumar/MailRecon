from pydantic import BaseModel
from typing import Optional, Literal
import uuid

class RiskScoreResponse(BaseModel):
    score: float
    confidence: float
    coverage: float
    uncertainty_label: str
    is_heuristic: Literal[True] = True
    summary: str

class AnalysisStatusResponse(BaseModel):
    case_id: uuid.UUID
    status: str
    progress_pct: Optional[float] = None


class AIAnalysisResponse(BaseModel):
    executive_summary: str
    attack_vector: str
    threat_actor_tactics: list[str]
    recommended_actions: list[str]
    evidence_citations: list[str]
    is_grounded: bool
    provider: str


class MacroKeywordItem(BaseModel):
    type: str
    keyword: str
    description: str


class MacroAnalysisItem(BaseModel):
    filename: str
    sha256: str
    has_macros: bool
    is_malicious: bool
    macro_count: int
    triggers: list[str] = []
    suspicious_keywords: list[MacroKeywordItem] = []
    extracted_iocs: list[dict] = []
    code_preview: str = ""
    error_message: Optional[str] = None


class MacroAnalysisListResponse(BaseModel):
    items: list[MacroAnalysisItem]
    total: int


class ObfuscationSection(BaseModel):
    original_preview: str = ""
    normalized_preview: str = ""
    has_evasion: bool = False
    zero_width_count: int = 0
    zero_width_chars: list[dict] = []
    rlo_detected: bool = False
    rlo_chars: list[dict] = []
    homoglyphs_detected: bool = False
    homoglyphs_found: list[dict] = []
    mixed_script_tokens: list[str] = []


class ObfuscationAnalysisResponse(BaseModel):
    has_evasion: bool
    body: ObfuscationSection
    subject: ObfuscationSection

