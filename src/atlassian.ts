import crypto from 'node:crypto';
export interface AtlassianConfig { clientId: string; clientSecret: string; redirectUri: string; scopes: string[]; siteUrl?: string; }
export interface AtlassianTokenSet { access_token: string; refresh_token?: string; expires_in?: number; scope?: string; expires_at: number; }
export interface AccessibleResource { id: string; url: string; name: string; scopes: string[]; }
const AUTHORIZATION_ENDPOINT='https://auth.atlassian.com/authorize';
const TOKEN_ENDPOINT='https://auth.atlassian.com/oauth/token';
const RESOURCES_ENDPOINT='https://api.atlassian.com/oauth/token/accessible-resources';
export class AtlassianOAuth {
  private token: AtlassianTokenSet|null=null;
  constructor(private readonly config: AtlassianConfig) {}
  authorizationUrl(state:string) { const p=new URLSearchParams({audience:'api.atlassian.com',client_id:this.config.clientId,scope:this.config.scopes.join(' '),redirect_uri:this.config.redirectUri,state,response_type:'code',prompt:'consent'}); return `${AUTHORIZATION_ENDPOINT}?${p}`; }
  async exchangeCode(code:string) { const r=await fetch(TOKEN_ENDPOINT,{method:'POST',headers:{'Content-Type':'application/json',Accept:'application/json'},body:JSON.stringify({grant_type:'authorization_code',client_id:this.config.clientId,client_secret:this.config.clientSecret,code,redirect_uri:this.config.redirectUri})}); return this.save(await this.parse(r)); }
  async refresh() { if(!this.token?.refresh_token) throw new Error('No Atlassian refresh token is available'); const r=await fetch(TOKEN_ENDPOINT,{method:'POST',headers:{'Content-Type':'application/json',Accept:'application/json'},body:JSON.stringify({grant_type:'refresh_token',client_id:this.config.clientId,client_secret:this.config.clientSecret,refresh_token:this.token.refresh_token})}); return this.save(await this.parse(r)); }
  async accessToken() { if(!this.token) throw new Error('Atlassian authorization is required'); if(Date.now()>=this.token.expires_at-60000) await this.refresh(); return this.token.access_token; }
  async accessibleResources() { const r=await fetch(RESOURCES_ENDPOINT,{headers:{Authorization:`Bearer ${await this.accessToken()}`,Accept:'application/json'}}); return this.parse(r) as Promise<AccessibleResource[]>; }
  hasAuthorization(){return this.token!==null;}
  private save(value:Omit<AtlassianTokenSet,'expires_at'>){this.token={...value,refresh_token:value.refresh_token??this.token?.refresh_token,expires_at:Date.now()+(value.expires_in??3600)*1000};return this.token;}
  private async parse(r:Response){const b=await r.text();let v:any={};try{v=b?JSON.parse(b):{};}catch{v={raw:b};}if(!r.ok)throw new Error(`Atlassian OAuth ${r.status}: ${JSON.stringify(v).slice(0,1000)}`);return v;}
}
export class AtlassianApi {
  constructor(private readonly oauth:AtlassianOAuth,private readonly cloudId:()=>Promise<string>){}
  async request<T>(product:'jira'|'confluence',path:string,init:RequestInit={}):Promise<T>{const r=await fetch(`https://api.atlassian.com/ex/${product}/${await this.cloudId()}${path}`,{...init,headers:{Accept:'application/json',...(init.body?{'Content-Type':'application/json'}:{}),Authorization:`Bearer ${await this.oauth.accessToken()}`,...(init.headers??{})}});const b=await r.text();let v:any={};try{v=b?JSON.parse(b):{};}catch{v={raw:b};}if(!r.ok)throw new Error(`Atlassian API ${r.status}: ${JSON.stringify(v).slice(0,1500)}`);return v as T;}
}
export function randomState(){return crypto.randomUUID();}
