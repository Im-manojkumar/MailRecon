export type Severity = 'info' | 'low' | 'medium' | 'high' | 'critical';

export const Severity = {
  INFO: 'info' as Severity,
  LOW: 'low' as Severity,
  MEDIUM: 'medium' as Severity,
  HIGH: 'high' as Severity,
  CRITICAL: 'critical' as Severity,
};

export type IndicatorKind = 'email' | 'domain' | 'ip' | 'url' | 'hash' | 'qr_url' | 'case';

export const IndicatorKind = {
  EMAIL: 'email' as IndicatorKind,
  DOMAIN: 'domain' as IndicatorKind,
  IP: 'ip' as IndicatorKind,
  URL: 'url' as IndicatorKind,
  HASH: 'hash' as IndicatorKind,
  QR_URL: 'qr_url' as IndicatorKind,
  CASE: 'case' as IndicatorKind,
};

export type CaseStatus = 'pending' | 'processing' | 'completed' | 'failed';

export const CaseStatus = {
  PENDING: 'pending' as CaseStatus,
  PROCESSING: 'processing' as CaseStatus,
  COMPLETED: 'completed' as CaseStatus,
  FAILED: 'failed' as CaseStatus,
};

export interface AnalystResponse {
  id: string;
  email: string;
  display_name?: string | null;
  is_active?: boolean;
}

export interface TokenResponse {
  access_token: string;
  token_type: string;
}

export interface CaseResponse {
  id: string;
  status: CaseStatus;
  original_sha256: string;
  original_size: number | null;
  filename: string | null;
  file_name?: string | null; // alias
  created_at: string;
  updated_at?: string | null;
}

export interface CaseDetail extends CaseResponse {
  analyst_id: string;
  metadata_json?: Record<string, any> | null;
}

export interface CaseListResponse {
  items: CaseResponse[];
  total: number;
  cases?: CaseResponse[]; // alias
}

export interface FindingResponse {
  id: string;
  case_id: string;
  detector: string;
  detector_name?: string; // alias
  severity: Severity;
  title: string;
  detail?: string | null;
  description?: string | null; // alias
  evidence_ref?: string | null;
  confidence: number;
  raw_evidence?: Record<string, any> | null;
  created_at: string;
}

export interface FindingListResponse {
  items: FindingResponse[];
  total: number;
  findings?: FindingResponse[]; // alias
}

export interface IndicatorResponse {
  id: string;
  case_id: string;
  kind: IndicatorKind;
  value: string;
  context?: string | null;
  first_seen_at?: string | null;
}

export interface IndicatorListResponse {
  items: IndicatorResponse[];
  total: number;
  indicators?: IndicatorResponse[]; // alias
}

export interface GraphNode {
  id: string;
  kind: string;
  value: string;
  label: string;
  risk_level: 'neutral' | 'suspicious' | 'malicious';
  metadata?: Record<string, any>;
  data?: {
    id: string;
    label: string;
    kind?: string;
    risk_level?: string;
  };
}

export interface GraphEdge {
  id: string;
  source: string;
  target: string;
  relationship: string;
  label?: string | null;
  data?: {
    id: string;
    source: string;
    target: string;
    relationship?: string;
    label?: string;
  };
}

export interface IndicatorGraphResponse {
  nodes: GraphNode[];
  edges: GraphEdge[];
}

export interface RiskScoreResponse {
  score: number;
  confidence: number;
  coverage: number;
  uncertainty_label: string;
  is_heuristic: boolean;
  summary: string;
}

export interface AnalysisStatusResponse {
  case_id: string;
  status: CaseStatus;
  progress_pct?: number | null;
}

export interface AIAnalysisResponse {
  executive_summary: string;
  attack_vector: string;
  threat_actor_tactics: string[];
  recommended_actions: string[];
  evidence_citations: string[];
  is_grounded: boolean;
  provider: string;
}

export interface GeoIPData {
  ip: string;
  country?: string | null;
  city?: string | null;
  asn?: string | null;
  org?: string | null;
  latitude?: number | null;
  longitude?: number | null;
  is_private: boolean;
}

export interface RouteHopEnrichment {
  hop: number;
  from_claimed?: string | null;
  by_node?: string | null;
  ip?: string | null;
  geoip?: GeoIPData | null;
  delay_seconds?: number | null;
  delay_display?: string | null;
  delay_anomaly?: string | null;
  tls_version?: string | null;
  cipher?: string | null;
  timestamp_iso?: string | null;
}

export interface RouteAnalysisResponse {
  hops: RouteHopEnrichment[];
  total_transit_seconds?: number | null;
  total_transit_display?: string | null;
  anomalies: string[];
}

export interface QrCodeResult {
  attachment_name: string;
  decoded_text: string;
  defanged_text: string;
  is_url: boolean;
}

export interface QrCodeListResponse {
  qr_codes: QrCodeResult[];
}

export interface ReportResponse {
  id: string;
  case_id: string;
  format: string;
  integrity_sha256?: string | null;
  created_at: string;
}

export interface ReportListResponse {
  items: ReportResponse[];
  total: number;
  reports?: ReportResponse[];
}

export interface AttachmentInfo {
  filename: string;
  content_type: string;
  size: number;
  sha256: string;
  is_macro: boolean;
  is_inline: boolean;
  content_id?: string | null;
  storage_key?: string | null;
}

export interface ExtractedUrl {
  url: string;
  defanged: string;
  domain: string;
  is_ip: boolean;
  source: string;
  anchor_text?: string | null;
  occurrences: number;
}

export interface ReceivedHop {
  hop_number: number;
  from_claimed?: string | null;
  by_node?: string | null;
  ip?: string | null;
  protocol?: string | null;
  is_tls: boolean;
  timestamp?: string | null;
  raw: string;
}

export interface ParsedEmailResponse {
  id: string;
  case_id: string;
  headers_json?: Record<string, any> | null;
  body_text?: string | null;
  body_html?: string | null;
  attachments_json?: AttachmentInfo[] | null;
  urls_json?: ExtractedUrl[] | null;
  auth_results_json?: Record<string, any> | null;
  received_chain_json?: ReceivedHop[] | null;
  parsed_at: string;
}

export interface MacroKeywordItem {
  type: string;
  keyword: string;
  description: string;
}

export interface MacroAnalysisItem {
  filename: string;
  sha256: string;
  has_macros: boolean;
  is_malicious: boolean;
  macro_count: number;
  triggers: string[];
  suspicious_keywords: MacroKeywordItem[];
  extracted_iocs: { type: string; value: string }[];
  code_preview: string;
  error_message?: string | null;
}

export interface MacroAnalysisListResponse {
  items: MacroAnalysisItem[];
  total: number;
}

export interface ObfuscationSection {
  original_preview: string;
  normalized_preview: string;
  has_evasion: boolean;
  zero_width_count: number;
  zero_width_chars: Record<string, any>[];
  rlo_detected: boolean;
  rlo_chars: Record<string, any>[];
  homoglyphs_detected: boolean;
  homoglyphs_found: Record<string, any>[];
  mixed_script_tokens: string[];
}

export interface ObfuscationAnalysisResponse {
  has_evasion: boolean;
  body: ObfuscationSection;
  subject: ObfuscationSection;
}
