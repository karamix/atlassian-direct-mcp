# Kostas Atlassian Direct

A private MCP server for Jira and Confluence Cloud.

## Initial scope

- Jira search and inspection
- Jira issue creation, updates, comments, and transitions
- Confluence page search and inspection
- Confluence page creation, updates, and comments
- Atlassian OAuth 2.0 (3LO) with refresh tokens
- No delete tools in the initial release

## Security

- No credentials belong in Git.
- OAuth tokens are handled server-side.
- Write tools use explicit typed inputs.
- Delete operations are not exposed.
- The host OAuth layer and Atlassian OAuth layer are separate.

## Persistent OAuth state

The server encrypts ChatGPT host tokens and Atlassian OAuth credentials with AES-256-GCM.
The encryption key is derived from `ATLASSIAN_CLIENT_SECRET`, so keep that secret stable;
rotating it requires a fresh Atlassian authorization.

For Render Free, create an Upstash Redis database and set `UPSTASH_REDIS_REST_URL`
and `UPSTASH_REDIS_REST_TOKEN` in the service environment. The server stores one
encrypted state value in Redis and restores it before accepting requests. The REST
token is a secret; never commit it. Leave Upstash eviction and auto-upgrade disabled
to avoid losing OAuth state or incurring charges when a quota is reached.

For local development, or another host with persistent storage, the server can use
`OAUTH_STATE_PATH`; its default is `.data/oauth-state.enc`. When Upstash variables
are configured, Redis takes precedence over the file path. Corrupt or undecryptable
state fails closed at startup.

## Required deployment secrets

Set these in the hosting provider, never in source control:

- ATLASSIAN_CLIENT_ID
- ATLASSIAN_CLIENT_SECRET
- MCP_OWNER_CONNECTION_SECRET (new: independent high-entropy secret, at least 32 characters)
- MCP_PUBLIC_URL
- ATLASSIAN_REDIRECT_URI
- ATLASSIAN_SITE_URL
- ATLASSIAN_SCOPES

The Atlassian callback URL must exactly match the value configured in the Atlassian Developer Console.

## Owner-gated ChatGPT authorization

Before deploying this release, configure `MCP_OWNER_CONNECTION_SECRET` in Render as a randomly generated secret (32+ characters, recommended 256-bit random). Do **not** use your Atlassian client secret, API token, or password. Never commit the value to Git. The service fails to start without this setting. Set the secret before redeploying, preferably with a controlled deployment step to avoid starting old source with an unrelated environment change.

ChatGPT's OAuth connection now displays an owner-secret form. An accepted ChatGPT client ID and a valid PKCE request are not proof of ownership. Only the holder of the owner connection secret can initiate issuance of a new MCP access/refresh token; on first Atlassian setup, the owner check also precedes Atlassian authorization. Previously issued host tokens are not revoked by this change; review existing connection grants and reset host token state if compromise is suspected (which will require reconnecting ChatGPT). The server continues using a single shared Atlassian OAuth grant, so it remains single-owner only, not multi-tenant.

Post-deployment verify: GET `/oauth/authorize` with valid OAuth parameters shows the owner form (does not redirect or issue a code); POST with a wrong/missing secret returns 403; POST with the correct secret completes the existing OAuth flow; unauthenticated `/mcp` returns 401. Do not automate live authorization attempts using your production credentials.

## Create a Jira issue

`jira_create_issue` takes `projectKey`, `issueTypeName`, and `summary`, plus optional
plain-text `description` and `labels`. It resolves the issue type against the
project's available types, converts description lines into ADF paragraphs, and
calls `POST /rest/api/3/issue`. The response contains the new issue's ID, key, and
API URL. For example:

```json
{
  "projectKey": "RUN",
  "issueTypeName": "Task",
  "summary": "TEST — Jira issue creation verification",
  "description": "Disposable test Task for MCP issue creation.",
  "labels": ["test"]
}
```

Subtasks and additional custom fields are outside this tool's scope. Projects
with other required creation fields will return Jira's validation error. The
existing `write:jira-work` grant and Jira Create Issues permission are required;
the tool does not add OAuth scopes. It is not idempotent: check Jira before
retrying a call whose outcome is uncertain.

Run `npm ci` and `npm test` to compile and exercise tool discovery, argument
validation, project/type resolution, ADF conversion, and Jira error propagation
through an in-memory MCP client. These tests do not create live Jira issues.

The remote plugin discovers tools from the existing `/mcp` endpoint; no plugin
manifest change is needed. After deploying the server update, refresh/reconnect
the plugin to discover the new tool. The encrypted OAuth state is restored from the configured persistent disk when the server starts. `/health`
includes the server version to help verify deployment.
