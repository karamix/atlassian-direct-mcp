import crypto from 'node:crypto';

export interface AtlassianConfig {
  clientId: string;
  clientSecret: string;
  redirectUri: string;
  scopes: string[];
  siteUrl?: string;
}

export interface AtlassianTokenSet {
  access_token: string;
  refresh_token?: string;
  expires_in?: number;
  scope?: string;
  expires_at: number;
}

export interface AccessibleResource {
  id: string;
  url: string;
  name: string;
  scopes: string[];
}

const AUTHORIZATION_ENDPOINT = 'https://auth.atlassian.com/authorize';
const TOKEN_ENDPOINT = 'https://auth.atlassian.com/oauth/token';
const RESOURCES_ENDPOINT = 'https://api.atlassian.com/oauth/token/accessible-resources';

export class AtlassianOAuth {
  private token: AtlassianTokenSet | null = null;

  constructor(private readonly config: AtlassianConfig) {}

  authorizationUrl(state: string): string {
    const params = new URLSearchParams({
      audience: 'api.atlassian.com',
      client_id: this.config.clientId,
      scope: this.config.scopes.join(' '),
      redirect_uri: this.config.redirectUri,
      state,
      response_type: 'code',
      prompt: 'consent'
    });
    return `${AUTHORIZATION_ENDPOINT}?${params.toString()}`;
  }

  async exchangeCode(code: string): Promise<AtlassianTokenSet> {
    const response = await fetch(TOKEN_ENDPOINT, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
      body: JSON.stringify({
        grant_type: 'authorization_code',
        client_id: this.config.clientId,
        client_secret: this.config.clientSecret,
        code,
        redirect_uri: this.config.redirectUri
      })
    });
    return this.saveToken(await this.parse(response));
  }

  async refresh(): Promise<AtlassianTokenSet> {
    if (!this.token?.refresh_token) {
      throw new Error('No Atlassian refresh token is available');
    }
    const response = await fetch(TOKEN_ENDPOINT, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
      body: JSON.stringify({
        grant_type: 'refresh_token',
        client_id: this.config.clientId,
        client_secret: this.config.clientSecret,
        refresh_token: this.token.refresh_token
      })
    });
    return this.saveToken(await this.parse(response));
  }

  async accessToken(): Promise<string> {
    if (!this.token) throw new Error('Atlassian authorization is required');
    if (Date.now() >= this.token.expires_at - 60_000) {
      await this.refresh();
    }
    return this.token.access_token;
  }

  async accessibleResources(): Promise<AccessibleResource[]> {
    const response = await fetch(RESOURCES_ENDPOINT, {
      headers: { Authorization: `Bearer ${await this.accessToken()}`, Accept: 'application/json' }
    });
    return this.parse(response) as Promise<AccessibleResource[]>;
  }

  hasAuthorization(): boolean {
    return this.token !== null;
  }

  private saveToken(value: Omit<AtlassianTokenSet, 'expires_at'>): AtlassianTokenSet {
    this.token = {
      ...value,
      expires_at: Date.now() + (value.expires_in ?? 3600) * 1000
    };
    return this.token;
  }

  private async parse(response: Response): Promise<any> {
    const body = await response.text();
    let value: any = {};
    try { value = body ? JSON.parse(body) : {}; } catch { value = { raw: body }; }
    if (!response.ok) {
      throw new Error(`Atlassian OAuth ${response.status}: ${JSON.stringify(value).slice(0, 1000)}`);
    }
    return value;
  }
}

export class AtlassianApi {
  constructor(
    private readonly oauth: AtlassianOAuth,
    private readonly cloudId: () => Promise<string>
  ) {}

  async request<T>(product: 'jira' | 'confluence', path: string, init: RequestInit = {}): Promise<T> {
    const response = await fetch(
      `https://api.atlassian.com/ex/${product}/${await this.cloudId()}${path}`,
      {
        ...init,
        headers: {
          Accept: 'application/json',
          ...(init.body ? { 'Content-Type': 'application/json' } : {}),
          Authorization: `Bearer ${await this.oauth.accessToken()}`,
          ...(init.headers ?? {})
        }
      }
    );
    const body = await response.text();
    let value: any = {};
    try { value = body ? JSON.parse(body) : {}; } catch { value = { raw: body }; }
    if (!response.ok) {
      throw new Error(`Atlassian API ${response.status}: ${JSON.stringify(value).slice(0, 1500)}`);
    }
    return value as T;
  }
}

export function randomState(): string {
  return crypto.randomBytes(32).toString('base64url');
}
