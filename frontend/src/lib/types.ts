export enum Severity {
  INFO = 'info',
  LOW = 'low',
  MEDIUM = 'medium',
  HIGH = 'high',
  CRITICAL = 'critical',
}

export enum IndicatorKind {
  IP = 'ip',
  DOMAIN = 'domain',
  URL = 'url',
  EMAIL = 'email',
  FILE_HASH = 'file_hash',
  KEYWORD = 'keyword',
}

export enum CaseStatus {
  PENDING = 'pending',
  PROCESSING = 'processing',
  COMPLETED = 'completed',
  FAILED = 'failed',
}

export interface AnalystResponse {
  id: string;
  email: string;
  display_name: string;
}

export interface TokenResponse {
  access_token: string;
  token_type: string;
}

export interface CaseResponse {
  id: string;
  status: CaseStatus;
  created_at: string;
}

export interface CaseDetail {
  id: string;
  status: CaseStatus;
  created_at: string;
  updated_at: string | null;
  file_name: string;
}

export interface CaseListResponse {
  cases: CaseDetail[];
  total: number;
}

export interface FindingResponse {
  id: string;
  case_id: string;
  detector_name: string;
  title: string;
  description: string;
  severity: Severity;
  confidence: number;
}

export interface FindingListResponse {
  findings: FindingResponse[];
}

export interface IndicatorResponse {
  id: string;
  case_id: string;
  kind: IndicatorKind;
  value: string;
  severity: Severity;
  tags: string[];
}

export interface IndicatorListResponse {
  indicators: IndicatorResponse[];
}

export interface GraphNode {
  data: {
    id: string;
    label: string;
    kind?: IndicatorKind | 'case';
    severity?: Severity;
  };
}

export interface GraphEdge {
  data: {
    id: string;
    source: string;
    target: string;
    label: string;
  };
}

export interface IndicatorGraphResponse {
  nodes: GraphNode[];
  edges: GraphEdge[];
}

export interface RiskScoreResponse {
  case_id: string;
  score: number;
  label: string;
  confidence: number;
}

export interface AnalysisStatusResponse {
  status: CaseStatus;
  progress: number;
  message: string;
}

export interface ReportResponse {
  id: string;
  case_id: string;
  content: string;
  format: string;
  created_at: string;
}

export interface ReportListResponse {
  reports: ReportResponse[];
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

