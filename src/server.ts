import 'dotenv/config';
import http from 'node:http';
import crypto from 'node:crypto';
import { AsyncLocalStorage } from 'node:async_hooks';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { z } from 'zod';
import { AtlassianApi, AtlassianOAuth, randomState } from './atlassian.js';
import { registerJiraCreateIssue } from './jira-create-issue.js';

const serviceVersion = '0.1.1';

const required = (name: string) => {
  const value = process.env[name];
  if (!value) throw new Error(`Missing required environment variable: ${name}`);
  return value;
};

const port = Number(process.env.PORT ?? 10000);
const publicUrl = required('MCP_PUBLIC_URL').replace(/\/$/, '');
const atlClientId = required('ATLASSIAN_CLIENT_ID');
const atlClientSecret = required('ATLASSIAN_CLIENT_SECRET');
const atlRedirectUri = required('ATLASSIAN_REDIRECT_URI');
const atlScopes = Array.from(new Set([
  ...(process.env.ATLASSIAN_SCOPES ?? '').split(/\s+/).filter(Boolean),
  'read:page:confluence',
  'write:page:confluence'
]));
const configuredSiteUrl = process.env.ATLASSIAN_SITE_URL?.replace(/\/$/, '');
const oauthIssuer = publicUrl;
const oauthResource = publicUrl;
const oauthScope = 'atlassian:access';

const atlassianOAuth = new AtlassianOAuth({
  clientId: atlClientId,
  clientSecret: atlClientSecret,
  redirectUri: atlRedirectUri,
  scopes: atlScopes,
  siteUrl: configuredSiteUrl
});

let cloudId: string | null = null;
const pendingAtlassian = new Map<string, PendingAuthorization>();
const authorizationCodes = new Map<string, AuthorizationCode>();
const accessTokens = new Map<string, number>();
const refreshTokens = new Set<string>();
const transports = new Map<string, StreamableHTTPServerTransport>();
const requestContext = new AsyncLocalStorage<http.IncomingMessage>();

type PendingAuthorization = {
  clientId: string;
  redirectUri: string;
  state: string;
  codeChallenge: string;
  resource: string;
  scope: string;
};

type AuthorizationCode = PendingAuthorization & { expiresAt: number };

function json(res: http.ServerResponse, status: number, body: unknown) {
  res.writeHead(status, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' });
  res.end(JSON.stringify(body));
}

function base64url(value: string | Buffer) {
  return Buffer.from(value).toString('base64url');
}

function sign(value: string) {
  return base64url(crypto.createHmac('sha256', atlClientSecret).update(value).digest());
}

function hostToken(type: 'access' | 'refresh', seconds: number) {
  const payload = base64url(JSON.stringify({ type, exp: Math.floor(Date.now() / 1000) + seconds, jti: crypto.randomUUID() }));
  return `${payload}.${sign(payload)}`;
}

function validHostToken(value: string, expected: 'access' | 'refresh') {
  const [payload, signature] = value.split('.');
  if (!payload || !signature || sign(payload) !== signature) return false;
  try {
    const decoded = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8')) as { type: string; exp: number };
    return decoded.type === expected && decoded.exp > Math.floor(Date.now() / 1000);
  } catch { return false; }
}

function validRedirect(uri: string) {
  try {
    const parsed = new URL(uri);
    if (parsed.protocol === 'https:' && parsed.hostname === 'chatgpt.com' && parsed.pathname === '/connector_platform_oauth_redirect') return true;
    if (parsed.protocol === 'https:' && parsed.hostname === 'chatgpt.com' && /^\/connector\/oauth\/[A-Za-z0-9_-]+$/.test(parsed.pathname)) return true;
    return parsed.protocol === 'http:' && (parsed.hostname === '127.0.0.1' || parsed.hostname === 'localhost') && parsed.pathname === '/callback' && Boolean(parsed.port) && !parsed.search && !parsed.hash;
  } catch { return false; }
}

function validClient(clientId: string) {
  return clientId === 'https://chatgpt.com/oauth/client.json' || clientId === 'https://chatgpt.com/oauth/codex/client.json';
}

function pkceChallenge(verifier: string) {
  return base64url(crypto.createHash('sha256').update(verifier).digest());
}

async function ensureCloudId() {
  if (cloudId) return cloudId;
  const resources = await atlassianOAuth.accessibleResources();
  const selected = configuredSiteUrl
    ? resources.find(resource => resource.url.replace(/\/$/, '') === configuredSiteUrl)
    : resources[0];
  if (!selected) throw new Error('Configured Atlassian site is not accessible to this OAuth app');
  cloudId = selected.id;
  return cloudId;
}

const api = new AtlassianApi(atlassianOAuth, ensureCloudId);
const issueKey = z.string().regex(/^[A-Z][A-Z0-9_]*-\d+$/);
const pageId = z.string().regex(/^\d+$/);

function text(value: unknown) {
  return { content: [{ type: 'text' as const, text: JSON.stringify(value, null, 2) }] };
}

function createMcpServer() {
  const server = new McpServer({ name: 'kostas-atlassian-direct', version: serviceVersion });
  registerJiraCreateIssue(server, api);
  server.registerTool('jira_search', { title: 'Search Jira', description: 'Search Jira with JQL.', inputSchema: { jql: z.string().min(1), maxResults: z.number().int().min(1).max(100).optional() } }, async ({ jql, maxResults }) => text(await api.request('jira', '/rest/api/3/search/jql', { method: 'POST', body: JSON.stringify({ jql, maxResults: maxResults ?? 50 }) })));
  server.registerTool('jira_get_project', { title: 'Get Jira project', description: 'Retrieve Jira project metadata, including available issue types.', inputSchema: { projectKey: z.string().regex(/^[A-Z][A-Z0-9_]*$/) } }, async ({ projectKey }) => text(await api.request('jira', `/rest/api/3/project/${encodeURIComponent(projectKey)}`)));
  server.registerTool('jira_get_issue', { title: 'Get Jira issue', description: 'Retrieve a Jira issue.', inputSchema: { issueKey: issueKey, fields: z.array(z.string()).optional() } }, async ({ issueKey: key, fields }) => text(await api.request('jira', `/rest/api/3/issue/${encodeURIComponent(key)}${fields?.length ? `?fields=${encodeURIComponent(fields.join(','))}` : ''}`)));
  server.registerTool('jira_update_issue', { title: 'Update Jira issue', description: 'Update selected Jira fields. No delete operations are exposed.', inputSchema: { issueKey, fields: z.object({ summary: z.string().min(1).max(255).optional(), description: z.string().max(20000).optional(), priority: z.string().max(100).optional(), labels: z.array(z.string().max(255)).max(50).optional() }).strict() } }, async ({ issueKey: key, fields }) => text(await api.request('jira', `/rest/api/3/issue/${encodeURIComponent(key)}`, { method: 'PUT', body: JSON.stringify({ fields: { ...fields, ...(fields.description ? { description: { type: 'doc', version: 1, content: [{ type: 'paragraph', content: [{ type: 'text', text: fields.description }] }] } } : {}) } }) })));
  server.registerTool('jira_add_comment', { title: 'Add Jira comment', description: 'Add a comment to a Jira issue.', inputSchema: { issueKey, body: z.string().min(1).max(10000) } }, async ({ issueKey: key, body }) => text(await api.request('jira', `/rest/api/3/issue/${encodeURIComponent(key)}/comment`, { method: 'POST', body: JSON.stringify({ body: { type: 'doc', version: 1, content: [{ type: 'paragraph', content: [{ type: 'text', text: body }] }] } }) })));
  server.registerTool('jira_transition_issue', { title: 'Transition Jira issue', description: 'Apply an available workflow transition.', inputSchema: { issueKey, transitionId: z.string().min(1) } }, async ({ issueKey: key, transitionId }) => text(await api.request('jira', `/rest/api/3/issue/${encodeURIComponent(key)}/transitions`, { method: 'POST', body: JSON.stringify({ transition: { id: transitionId } }) })));
  server.registerTool('confluence_search', { title: 'Search Confluence', description: 'Search Confluence pages with CQL.', inputSchema: { cql: z.string().min(1), limit: z.number().int().min(1).max(100).optional() } }, async ({ cql, limit }) => text(await api.request('confluence', `/wiki/rest/api/content/search?cql=${encodeURIComponent(cql)}&limit=${limit ?? 25}`)));
  server.registerTool('confluence_get_page', { title: 'Get Confluence page', description: 'Retrieve a Confluence page.', inputSchema: { pageId } }, async ({ pageId: id }) => text(await api.request('confluence', `/wiki/api/v2/pages/${id}?body-format=storage`)));
  server.registerTool('confluence_create_page', { title: 'Create Confluence page', description: 'Create a page in a Confluence space.', inputSchema: { spaceId: z.string().min(1), title: z.string().min(1).max(255), body: z.string().min(1) } }, async ({ spaceId, title, body }) => text(await api.request('confluence', '/wiki/api/v2/pages', { method: 'POST', body: JSON.stringify({ spaceId, title, status: 'current', body: { representation: 'storage', value: body } }) })));
  server.registerTool('confluence_update_page', { title: 'Update Confluence page', description: 'Update a page and increment its version.', inputSchema: { pageId, title: z.string().min(1).max(255), body: z.string().min(1), version: z.number().int().min(1), versionMessage: z.string().max(500).optional() } }, async ({ pageId: id, title, body, version, versionMessage }) => text(await api.request('confluence', `/wiki/api/v2/pages/${id}`, { method: 'PUT', body: JSON.stringify({ id, title, status: 'current', body: { representation: 'storage', value: body }, version: { number: version + 1, message: versionMessage ?? 'Updated by Kostas Atlassian Direct' } }) })));
  server.registerTool('confluence_add_comment', { title: 'Add Confluence comment', description: 'Add a footer comment to a page.', inputSchema: { pageId, body: z.string().min(1).max(10000) } }, async ({ pageId: id, body }) => text(await api.request('confluence', `/wiki/rest/api/content/${id}/child/comment`, { method: 'POST', body: JSON.stringify({ type: 'comment', container: { id, type: 'page' }, body: { storage: { value: body, representation: 'storage' } } }) })));
  return server;
}

function redirectWithCode(res: http.ServerResponse, pending: PendingAuthorization) {
  const code = crypto.randomBytes(32).toString('base64url');
  authorizationCodes.set(code, { ...pending, expiresAt: Date.now() + 300_000 });
  const target = new URL(pending.redirectUri);
  target.searchParams.set('code', code);
  target.searchParams.set('state', pending.state);
  target.searchParams.set('iss', oauthIssuer);
  res.writeHead(302, { Location: target.toString(), 'Cache-Control': 'no-store' });
  res.end();
}

async function handleAuthorize(req: http.IncomingMessage, res: http.ServerResponse) {
  const url = new URL(req.url ?? '/', publicUrl);
  const form = req.method === 'POST' ? new URLSearchParams(await readBody(req)) : url.searchParams;
  const pending: PendingAuthorization = {
    clientId: form.get('client_id') ?? '', redirectUri: form.get('redirect_uri') ?? '', state: form.get('state') ?? '', codeChallenge: form.get('code_challenge') ?? '', resource: form.get('resource') ?? '', scope: form.get('scope') ?? oauthScope
  };
  if (!validClient(pending.clientId) || !validRedirect(pending.redirectUri) || pending.resource !== oauthResource || !pending.codeChallenge || form.get('code_challenge_method') !== 'S256') return json(res, 400, { error: 'invalid_request', error_description: 'Invalid OAuth client, redirect, resource, or PKCE parameters' });
  if (!atlassianOAuth.hasAuthorization()) {
    const atlState = randomState();
    pendingAtlassian.set(atlState, pending);
    res.writeHead(302, { Location: atlassianOAuth.authorizationUrl(atlState), 'Cache-Control': 'no-store' });
    return res.end();
  }
  redirectWithCode(res, pending);
}

async function handleAtlassianCallback(req: http.IncomingMessage, res: http.ServerResponse) {
  const url = new URL(req.url ?? '/', publicUrl);
  const state = url.searchParams.get('state') ?? '';
  const pending = pendingAtlassian.get(state);
  if (!pending) return json(res, 400, { error: 'invalid_request', error_description: 'Unknown Atlassian OAuth state' });
  pendingAtlassian.delete(state);
  const code = url.searchParams.get('code');
  if (!code) return json(res, 400, { error: 'access_denied', error_description: url.searchParams.get('error_description') ?? 'Atlassian authorization denied' });
  await atlassianOAuth.exchangeCode(code);
  cloudId = null;
  redirectWithCode(res, pending);
}

async function handleToken(req: http.IncomingMessage, res: http.ServerResponse) {
  const body = await readBody(req);
  const params = new URLSearchParams(body);
  if (params.get('grant_type') === 'refresh_token') {
    const supplied = params.get('refresh_token') ?? '';
    if (!refreshTokens.has(supplied) || !validHostToken(supplied, 'refresh')) return json(res, 400, { error: 'invalid_grant' });
    refreshTokens.delete(supplied);
    const access = hostToken('access', 3600);
    const refresh = hostToken('refresh', 60 * 60 * 24 * 30);
    accessTokens.set(access, Date.now() + 3_600_000);
    refreshTokens.add(refresh);
    return json(res, 200, { access_token: access, refresh_token: refresh, token_type: 'Bearer', expires_in: 3600, scope: oauthScope });
  }
  const code = params.get('code') ?? '';
  const record = authorizationCodes.get(code);
  if (!record || record.expiresAt < Date.now()) return json(res, 400, { error: 'invalid_grant' });
  authorizationCodes.delete(code);
  if (params.get('client_id') !== record.clientId || params.get('redirect_uri') !== record.redirectUri || pkceChallenge(params.get('code_verifier') ?? '') !== record.codeChallenge) return json(res, 400, { error: 'invalid_grant' });
  const access = hostToken('access', 3600);
  const refresh = hostToken('refresh', 60 * 60 * 24 * 30);
  accessTokens.set(access, Date.now() + 3_600_000);
  refreshTokens.add(refresh);
  return json(res, 200, { access_token: access, refresh_token: refresh, token_type: 'Bearer', expires_in: 3600, scope: oauthScope });
}

async function readBody(req: http.IncomingMessage) {
  const chunks: Buffer[] = [];
  for await (const chunk of req) chunks.push(Buffer.from(chunk));
  return Buffer.concat(chunks).toString('utf8');
}

function authorized(req: http.IncomingMessage) {
  const header = req.headers.authorization ?? '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : '';
  return accessTokens.has(token) && (accessTokens.get(token) ?? 0) > Date.now();
}

const server = http.createServer(async (req, res) => {
  try {
    const path = new URL(req.url ?? '/', publicUrl).pathname;
    if (path === '/health') return json(res, 200, { ok: true, service: 'kostas-atlassian-direct', version: serviceVersion });
    if (path === '/.well-known/oauth-authorization-server') return json(res, 200, { issuer: oauthIssuer, authorization_endpoint: `${publicUrl}/oauth/authorize`, token_endpoint: `${publicUrl}/oauth/token`, authorization_response_iss_parameter_supported: true, client_id_metadata_document_supported: true, token_endpoint_auth_methods_supported: ['none'], code_challenge_methods_supported: ['S256'], scopes_supported: [oauthScope, 'offline_access'] });
    if (path === '/.well-known/oauth-protected-resource') return json(res, 200, { resource: oauthResource, authorization_servers: [oauthIssuer], scopes_supported: [oauthScope] });
    if (path === '/oauth/authorize' && (req.method === 'GET' || req.method === 'POST')) return await handleAuthorize(req, res);
    if (path === '/oauth/atlassian/callback' && req.method === 'GET') return await handleAtlassianCallback(req, res);
    if (path === '/oauth/token' && req.method === 'POST') return await handleToken(req, res);
    if (path === '/mcp') {
      if (!authorized(req)) {
        res.setHeader('WWW-Authenticate', `Bearer resource_metadata="${publicUrl}/.well-known/oauth-protected-resource", scope="${oauthScope}"`);
        return json(res, 401, { error: 'unauthorized' });
      }
      const sessionId = req.headers['mcp-session-id'] as string | undefined;
      let transport = sessionId ? transports.get(sessionId) : undefined;
      if (!transport) {
        transport = new StreamableHTTPServerTransport({ sessionIdGenerator: () => crypto.randomUUID(), onsessioninitialized: id => { transports.set(id, transport!); } });
        transport.onclose = () => { if (transport?.sessionId) transports.delete(transport.sessionId); };
        await createMcpServer().connect(transport);
      }
      return await requestContext.run(req, () => transport!.handleRequest(req, res));
    }
    json(res, 404, { error: 'not_found' });
  } catch (error) {
    console.error('[server] request failed', error);
    json(res, 500, { error: 'server_error', error_description: error instanceof Error ? error.message : 'Unknown error' });
  }
});

server.listen(port, '0.0.0.0', () => console.log(`kostas-atlassian-direct listening on http://localhost:${port}`));
