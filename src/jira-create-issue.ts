import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import type { AtlassianApi } from './atlassian.js';

type JiraProject = { issueTypes: { id: string; name: string; subtask: boolean }[] };
type CreatedIssue = { id: string; key: string; self: string };

export function registerJiraCreateIssue(server: McpServer, api: Pick<AtlassianApi, 'request'>) {
  server.registerTool('jira_create_issue', {
    title: 'Create Jira issue',
    description: 'Create a Jira issue using an issue type available in the project. Supports summary, plain-text description, and labels. Subtasks and custom required fields are not supported. This creates a new issue each time; do not retry after an uncertain result without checking Jira.',
    inputSchema: {
      projectKey: z.string().regex(/^[A-Z][A-Z0-9_]*$/),
      issueTypeName: z.string().trim().min(1).max(100),
      summary: z.string().trim().min(1).max(255),
      description: z.string().min(1).max(20000).optional(),
      labels: z.array(z.string().min(1).max(255).regex(/^\S+$/)).max(50).optional()
    },
    annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: true }
  }, async ({ projectKey, issueTypeName, summary, description, labels }) => {
    const project = await api.request<JiraProject>('jira', `/rest/api/3/project/${encodeURIComponent(projectKey)}`);
    const matches = project.issueTypes.filter(type => type.name.toLowerCase() === issueTypeName.toLowerCase());
    if (matches.length !== 1) {
      const available = project.issueTypes.filter(type => !type.subtask).map(type => type.name).join(', ');
      throw new Error(`Issue type "${issueTypeName}" is unavailable or ambiguous in ${projectKey}. Available non-subtask types: ${available}`);
    }
    const type = matches[0]!;
    if (type.subtask) throw new Error('Subtasks require a parent and are not supported by jira_create_issue. Select a non-subtask issue type.');
    const fields = {
      project: { key: projectKey },
      issuetype: { id: type.id },
      summary,
      ...(description !== undefined ? { description: {
        type: 'doc', version: 1,
        content: description.split(/\r?\n/).map(line => ({
          type: 'paragraph', content: line ? [{ type: 'text', text: line }] : []
        }))
      } } : {}),
      ...(labels !== undefined ? { labels } : {})
    };
    const created = await api.request<CreatedIssue>('jira', '/rest/api/3/issue', {
      method: 'POST', body: JSON.stringify({ fields })
    });
    return { content: [{ type: 'text' as const, text: JSON.stringify(created, null, 2) }] };
  });
}
