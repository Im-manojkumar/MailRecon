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


class DomainIntelResponse(BaseModel):
    domain: str
    registrar: Optional[str] = None
    created_at_iso: Optional[str] = None
    expires_at_iso: Optional[str] = None
    domain_age_days: Optional[int] = None
    is_newly_registered: bool = False
    is_recent: bool = False
    risk_level: str = "unknown"
    status: list[str] = []


class LiveDnsValidationResponse(BaseModel):
    domain: str
    dns_resolved: bool
    spf: dict
    dmarc: dict
    mx: dict
    alignment: dict
    message_id_valid: bool
    anomalies: list[str] = []


class OriginProfileResponse(BaseModel):
    originating_ip: Optional[str] = None
    country: Optional[str] = None
    country_code: Optional[str] = None
    city: Optional[str] = None
    isp: Optional[str] = None
    org: Optional[str] = None
    asn: Optional[str] = None
    infra_type: Optional[str] = None
    infra_label: Optional[str] = None
    origin_confidence: str = "inconclusive"
    is_anonymized: bool = False


class FinancialForensicsResponse(BaseModel):
    is_financial_threat: bool
    risk_level: str = "none"
    bank_accounts: list[str] = []
    routing_numbers: list[str] = []
    swift_codes: list[str] = []
    crypto_wallets: list[dict] = []
    amounts_mentioned: list[str] = []
    invoice_numbers: list[str] = []
    diversion_indicators: list[str] = []
    vendor_mismatch: Optional[str] = None
    threat_score: float = 0.0


class ThreatClassificationResponse(BaseModel):
    primary_category: str
    category_label: str
    confidence: float
    secondary_categories: list[dict] = []
    justification: list[str] = []
    action_summary: str


class PlaybookItem(BaseModel):
    action_id: str
    pillar: str
    pillar_label: str = ""
    priority: str
    title: str
    description: str
    target_asset: str = ""
    automated_script: Optional[str] = None
    script_language: Optional[str] = None
    manual_steps: list[str] = []
    completed: bool = False


class PlaybookResponse(BaseModel):
    case_id: str
    total_actions: int = 0
    completed_actions: int = 0
    critical_actions: int = 0
    items: list[PlaybookItem] = []


class PlaybookToggleRequest(BaseModel):
    action_id: str
    completed: bool




