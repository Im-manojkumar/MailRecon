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
  ReportListResponse,
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
      const formData = new URLSearchParams();
      formData.append('username', email); // OAuth2 password flow typically uses 'username'
      formData.append('password', password);
      
      const res = await fetch(`${this.baseUrl}/api/auth/token`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: formData.toString(),
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
      const res = await this.fetchAuth('/api/cases/upload', {
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
    getParsed: async (id: string): Promise<any> => {
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
    generateReport: async (id: string): Promise<void> => {
      await this.fetchAuth(`/api/cases/${id}/reports`, { method: 'POST' });
    },
    getReports: async (id: string): Promise<ReportListResponse> => {
      const res = await this.fetchAuth(`/api/cases/${id}/reports`);
      return res.json();
    },
    downloadOriginal: async (id: string): Promise<Blob> => {
      const res = await this.fetchAuth(`/api/cases/${id}/download`);
      return res.blob();
    }
  };
}

export const api = new ApiClient(process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000');
