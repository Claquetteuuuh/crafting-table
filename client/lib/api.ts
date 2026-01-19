import {
    ShellcodeRequest,
    ShellcodeResponse,
    PayloadRequest,
    PayloadResponse,
    CompileRequest,
    CompileResponse,
    IATFunctionsResponse,
} from './types';

const API_BASE_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:3000/api';

class APIClient {
    private baseUrl: string;

    constructor(baseUrl: string = API_BASE_URL) {
        this.baseUrl = baseUrl;
    }

    private async request<T>(
        endpoint: string,
        options: RequestInit = {}
    ): Promise<T> {
        const url = `${this.baseUrl}${endpoint}`;

        const response = await fetch(url, {
            ...options,
            headers: {
                'Content-Type': 'application/json',
                ...options.headers,
            },
        });

        if (!response.ok) {
            const error = await response.json().catch(() => ({ error: 'Request failed' }));
            throw new Error(error.error || error.details || `HTTP ${response.status}`);
        }

        return response.json();
    }

    async generateShellcode(request: ShellcodeRequest): Promise<ShellcodeResponse> {
        return this.request<ShellcodeResponse>('/msfvenom-shellcode', {
            method: 'POST',
            body: JSON.stringify(request),
        });
    }

    async generatePayload(request: PayloadRequest): Promise<PayloadResponse> {
        return this.request<PayloadResponse>('/generate-payload', {
            method: 'POST',
            body: JSON.stringify(request),
        });
    }

    async compileCode(request: CompileRequest): Promise<CompileResponse> {
        return this.request<CompileResponse>('/compile', {
            method: 'POST',
            body: JSON.stringify(request),
        });
    }

    async getIATFunctions(): Promise<IATFunctionsResponse> {
        return this.request<IATFunctionsResponse>('/iat-functions', {
            method: 'GET',
        });
    }
}

export const apiClient = new APIClient();
