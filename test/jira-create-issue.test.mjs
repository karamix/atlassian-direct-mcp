import assert from 'node:assert/strict';
import test from 'node:test';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { registerJiraCreateIssue } from '../dist/jira-create-issue.js';

const issueTypes = [
  { id: '10008', name: 'Task', subtask: false },
  { id: '10009', name: 'Story', subtask: false },
  { id: '10007', name: 'Subtask', subtask: true }
];
const basic = { projectKey: 'RUN', issueTypeName: 'Task', summary: 'Test task' };

async function fixture(t, { types = issueTypes, createError } = {}) {
  const calls = [];
  const server = new McpServer({ name: 'test', version: '1.0.0' });
  registerJiraCreateIssue(server, {
    async request(product, path, init = {}) {
      calls.push({ product, path, init });
      if (path === '/rest/api/3/project/RUN') return { issueTypes: types };
      assert.equal(path, '/rest/api/3/issue');
      assert.equal(init.method, 'POST');
      if (createError) throw new Error(createError);
      return { id: '123', key: 'RUN-123', self: 'https://example.test/rest/api/3/issue/123' };
    }
  });
  const client = new Client({ name: 'test-client', version: '1.0.0' });
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  await server.connect(serverTransport);
  await client.connect(clientTransport);
  t.after(async () => { await client.close(); await server.close(); });
  const call = args => client.callTool({ name: 'jira_create_issue', arguments: args });
  return { client, calls, call };
}

test('discovers required inputs and non-idempotent write annotations', async t => {
  const { client } = await fixture(t);
  const { tools } = await client.listTools();
  assert.equal(tools.length, 1);
  assert.equal(tools[0].name, 'jira_create_issue');
  assert.deepEqual(tools[0].inputSchema.required.sort(), ['issueTypeName', 'projectKey', 'summary']);
  assert.equal(tools[0].annotations.readOnlyHint, false);
  assert.equal(tools[0].annotations.idempotentHint, false);
});

test('creates using the project type ID and preserves plain text as multiline ADF', async t => {
  const { calls, call } = await fixture(t);
  const result = await call({ ...basic, issueTypeName: ' task ', summary: ' Test task ', description: 'First line\r\n\n<script>literal text</script>', labels: ['test', 'mcp'] });
  assert.ok(!result.isError);
  assert.equal(JSON.parse(result.content[0].text).key, 'RUN-123');
  assert.equal(calls.length, 2);
  assert.equal(calls[0].product, 'jira');
  assert.deepEqual(JSON.parse(calls[1].init.body), { fields: {
    project: { key: 'RUN' }, issuetype: { id: '10008' }, summary: 'Test task',
    description: { type: 'doc', version: 1, content: [
      { type: 'paragraph', content: [{ type: 'text', text: 'First line' }] },
      { type: 'paragraph', content: [] },
      { type: 'paragraph', content: [{ type: 'text', text: '<script>literal text</script>' }] }
    ] }, labels: ['test', 'mcp']
  } });
});

test('omits optional fields and sends exactly one create request', async t => {
  const { calls, call } = await fixture(t);
  await call(basic);
  assert.deepEqual(JSON.parse(calls[1].init.body), { fields: {
    project: { key: 'RUN' }, issuetype: { id: '10008' }, summary: 'Test task'
  } });
  assert.equal(calls.filter(c => c.init.method === 'POST').length, 1);
});

test('rejects invalid arguments before reaching Jira', async t => {
  const { calls, call } = await fixture(t);
  for (const invalid of [
    { ...basic, projectKey: 'RUN/../OTHER' },
    { ...basic, summary: '   ' },
    { ...basic, summary: 'a'.repeat(256) },
    { ...basic, labels: ['two words'] },
    { ...basic, labels: [''] },
    { ...basic, issueTypeName: '' },
    { projectKey: 'RUN', summary: 'Missing issue type' }
  ]) {
    const result = await call(invalid);
    assert.equal(result.isError, true);
  }
  assert.equal(calls.length, 0);
});

test('unknown and subtask types never produce a create request', async t => {
  const { calls, call } = await fixture(t);
  const unknown = await call({ ...basic, issueTypeName: 'Unknown' });
  assert.equal(unknown.isError, true);
  assert.match(unknown.content[0].text, /Task, Story/);
  const subtask = await call({ ...basic, issueTypeName: 'Subtask' });
  assert.equal(subtask.isError, true);
  assert.match(subtask.content[0].text, /require a parent/);
  assert.ok(calls.every(c => c.init.method !== 'POST'));
});

test('ambiguous types are rejected before creation', async t => {
  const { calls, call } = await fixture(t, { types: [...issueTypes, { id: '999', name: 'TASK', subtask: false }] });
  const result = await call(basic);
  assert.equal(result.isError, true);
  assert.equal(calls.length, 1);
});

test('surfaces Jira permission/required-field errors without retrying creation', async t => {
  const { calls, call } = await fixture(t, { createError: 'Atlassian API 400: customfield_123 is required' });
  const result = await call(basic);
  assert.equal(result.isError, true);
  assert.match(result.content[0].text, /customfield_123 is required/);
  assert.equal(calls.length, 2);
});
