import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

// Source-level regression guard for the authentication boundary. Runtime behavior
// must also be verified against a test server before production deployment.
test('owner gate precedes all authorization-code issuance and Atlassian redirect', async () => {
  const source = await readFile(new URL('../src/server.ts', import.meta.url), 'utf8');
  const handler = source.slice(source.indexOf('async function handleAuthorize('), source.indexOf('async function handleAtlassianCallback('));
  assert.ok(handler.includes("if (req.method === 'GET') return showOwnerAuthorizationForm(res, form);"));
  const guard = handler.indexOf('if (!validOwnerConnectionSecret(');
  assert.ok(guard > 0);
  assert.ok(guard < handler.indexOf('atlassianOAuth.hasAuthorization()'));
  assert.ok(guard < handler.indexOf('redirectWithCode(res, pending)'));
  assert.ok(handler.includes("return json(res, 403, { error: 'access_denied'"));
});

test('owner secret must be independently configured and host redirect remains restricted', async () => {
  const source = await readFile(new URL('../src/server.ts', import.meta.url), 'utf8');
  assert.match(source, /required\('MCP_OWNER_CONNECTION_SECRET'\)/);
  assert.match(source, /ownerConnectionSecret\.length < 32/);
  assert.match(source, /ownerConnectionSecret === atlClientSecret/);
  assert.match(source, /crypto\.timingSafeEqual\(expectedDigest, suppliedDigest\)/);
  assert.match(source, /parsed\.hostname === 'chatgpt\.com'/);
});
