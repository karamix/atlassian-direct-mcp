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

For Render, attach a persistent disk mounted at `/var/data` and set
`OAUTH_STATE_PATH=/var/data/oauth-state.enc` before deploying. The default local
development path is `.data/oauth-state.enc`. Without a persistent disk, the file is
lost when the service is replaced or restarted, and the connection will still need
authorization again. Corrupt or undecryptable state fails closed at startup.

## Required deployment secrets

Set these in the hosting provider, never in source control:

- ATLASSIAN_CLIENT_ID
- ATLASSIAN_CLIENT_SECRET
- MCP_PUBLIC_URL
- ATLASSIAN_REDIRECT_URI
- ATLASSIAN_SITE_URL
- ATLASSIAN_SCOPES

The Atlassian callback URL must exactly match the value configured in the Atlassian Developer Console.

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
the plugin to discover the new tool. Server restarts clear the current in-memory
OAuth state, so reconnection may require Atlassian consent again. `/health`
includes the server version to help verify deployment.
