import {
  TokenResponse,
  AnalystResponse,
  CaseResponse,
  CaseListResponse,
  CaseDetail,
  FindingListResponse,
  IndicatorListResponse,
  IndicatorGraphResponse,
  RiskScoreResponse,
  ReportResponse,
  ReportListResponse,
  AIAnalysisResponse,
  RouteAnalysisResponse,
  QrCodeResult,
  ParsedEmailResponse,
  MacroAnalysisListResponse,
  ObfuscationAnalysisResponse,
  DomainIntelResponse,
  LiveDnsValidationResponse,
  OriginProfileResponse,
  ThreatClassificationResponse,
  FinancialForensicsResponse,
  PlaybookResponse,
  CampaignListResponse,
  CampaignDetail,
  CaseCampaignAffiliation,
} from './types';

class ApiClient {
  private baseUrl: string;

  constructor(baseUrl: string) {
    this.baseUrl = baseUrl;
  }

  private async fetchAuth(endpoint: string, options: RequestInit = {}): Promise<Response> {
    const token = typeof window !== 'undefined' ? localStorage.getItem('token') : null;
    const headers = new Headers(options.headers || {});
    if (token) {
      headers.set('Authorization', `Bearer ${token}`);
    }
    
    const response = await fetch(`${this.baseUrl}${endpoint}`, {
      ...options,
      headers,
    });
    
    if (!response.ok) {
      const errMessage = await response.text();
      throw new Error(errMessage || `Request failed with status ${response.status}`);
    }
    return response;
  }

  auth = {
    login: async (email: string, password: string): Promise<TokenResponse> => {
      const res = await fetch(`${this.baseUrl}/api/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password }),
      });
      if (!res.ok) throw new Error('Login failed');
      return res.json();
    },
    register: async (email: string, password: string, displayName: string): Promise<TokenResponse> => {
      const res = await fetch(`${this.baseUrl}/api/auth/register`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password, display_name: displayName }),
      });
      if (!res.ok) throw new Error('Registration failed');
      return res.json();
    },
    me: async (): Promise<AnalystResponse> => {
      const res = await this.fetchAuth('/api/auth/me');
      return res.json();
    }
  };

  cases = {
    upload: async (file: File): Promise<CaseResponse> => {
      const formData = new FormData();
      formData.append('file', file);
      const res = await this.fetchAuth('/api/cases', {
        method: 'POST',
        body: formData,
      });
      return res.json();
    },
    list: async (): Promise<CaseListResponse> => {
      const res = await this.fetchAuth('/api/cases');
      return res.json();
    },
    get: async (id: string): Promise<CaseDetail> => {
      const res = await this.fetchAuth(`/api/cases/${id}`);
      return res.json();
    },
    getParsed: async (id: string): Promise<ParsedEmailResponse> => {
      const res = await this.fetchAuth(`/api/cases/${id}/parsed`);
      return res.json();
    },
    getFindings: async (id: string): Promise<FindingListResponse> => {
      const res = await this.fetchAuth(`/api/cases/${id}/findings`);
      return res.json();
    },
    getIndicators: async (id: string): Promise<IndicatorListResponse> => {
      const res = await this.fetchAuth(`/api/cases/${id}/indicators`);
      return res.json();
    },
    getGraph: async (id: string): Promise<IndicatorGraphResponse> => {
      const res = await this.fetchAuth(`/api/cases/${id}/graph`);
      return res.json();
    },
    getScore: async (id: string): Promise<RiskScoreResponse> => {
      const res = await this.fetchAuth(`/api/cases/${id}/score`);
      return res.json();
    },
    getAIAnalysis: async (id: string): Promise<AIAnalysisResponse> => {
      const res = await this.fetchAuth(`/api/cases/${id}/ai-analysis`);
      return res.json();
    },
    getRoute: async (id: string): Promise<RouteAnalysisResponse> => {
      const res = await this.fetchAuth(`/api/cases/${id}/route`);
      return res.json();
    },
    getQrCodes: async (id: string): Promise<QrCodeResult[]> => {
      const res = await this.fetchAuth(`/api/cases/${id}/qr-codes`);
      return res.json();
    },
    generateReport: async (id: string, format: 'html' | 'json' = 'html'): Promise<ReportResponse> => {
      const res = await this.fetchAuth(`/api/cases/${id}/report?format=${format}`, { method: 'POST' });
      return res.json();
    },
    getReports: async (id: string): Promise<ReportListResponse> => {
      const res = await this.fetchAuth(`/api/cases/${id}/reports`);
      return res.json();
    },
    downloadReport: async (caseId: string, reportId: string): Promise<Blob> => {
      const res = await this.fetchAuth(`/api/cases/${caseId}/reports/${reportId}`);
      return res.blob();
    },
    getMacros: async (id: string): Promise<MacroAnalysisListResponse> => {
      const res = await this.fetchAuth(`/api/cases/${id}/macros`);
      return res.json();
    },
    getObfuscation: async (id: string): Promise<ObfuscationAnalysisResponse> => {
      const res = await this.fetchAuth(`/api/cases/${id}/obfuscation`);
      return res.json();
    },
    getDomainIntel: async (id: string): Promise<DomainIntelResponse> => {
      const res = await this.fetchAuth(`/api/cases/${id}/domain-intel`);
      return res.json();
    },
    getDnsValidation: async (id: string): Promise<LiveDnsValidationResponse> => {
      const res = await this.fetchAuth(`/api/cases/${id}/dns-validation`);
      return res.json();
    },
    getOriginProfile: async (id: string): Promise<OriginProfileResponse> => {
      const res = await this.fetchAuth(`/api/cases/${id}/origin-profile`);
      return res.json();
    },
    getThreatClassification: async (id: string): Promise<ThreatClassificationResponse> => {
      const res = await this.fetchAuth(`/api/cases/${id}/threat-category`);
      return res.json();
    },
    getFinancialForensics: async (id: string): Promise<FinancialForensicsResponse> => {
      const res = await this.fetchAuth(`/api/cases/${id}/financial-forensics`);
      return res.json();
    },
    getPlaybook: async (id: string): Promise<PlaybookResponse> => {
      const res = await this.fetchAuth(`/api/cases/${id}/playbook`);
      return res.json();
    },
    togglePlaybookAction: async (id: string, actionId: string, completed: boolean): Promise<PlaybookResponse> => {
      const res = await this.fetchAuth(`/api/cases/${id}/playbook/toggle`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ action_id: actionId, completed }),
      });
      return res.json();
    },
    getExportContent: async (id: string, format: 'stix' | 'yara' | 'sigma' | 'snort'): Promise<string> => {
      const res = await this.fetchAuth(`/api/cases/${id}/export/${format}`);
      return res.text();
    },
    downloadOriginal: async (id: string): Promise<Blob> => {
      const res = await this.fetchAuth(`/api/cases/${id}/original`);
      return res.blob();
    },
    getCampaign: async (id: string): Promise<CaseCampaignAffiliation> => {
      const res = await this.fetchAuth(`/api/cases/${id}/campaign`);
      return res.json();
    }
  };

  campaigns = {
    list: async (): Promise<CampaignListResponse> => {
      const res = await this.fetchAuth('/api/campaigns');
      return res.json();
    },
    get: async (id: string): Promise<CampaignDetail> => {
      const res = await this.fetchAuth(`/api/campaigns/${id}`);
      return res.json();
    },
  };
}

export const api = new ApiClient(process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000');
