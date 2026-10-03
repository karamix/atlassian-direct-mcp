# Kostas Atlassian Direct

A private MCP server for Jira and Confluence Cloud.

## Initial scope

- Jira search and inspection
- Jira issue updates, comments, links, and transitions
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

## Required deployment secrets

Set these in the hosting provider, never in source control:

- ATLASSIAN_CLIENT_ID
- ATLASSIAN_CLIENT_SECRET
- MCP_PUBLIC_URL
- ATLASSIAN_REDIRECT_URI
- ATLASSIAN_SITE_URL
- ATLASSIAN_SCOPES

The Atlassian callback URL must exactly match the value configured in the Atlassian Developer Console.
