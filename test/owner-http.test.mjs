import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdtemp, rm } from 'node:fs/promises';
import { createServer } from 'node:net';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

async function freePort() {
  return await new Promise((resolve, reject) => {
    const s = createServer();
    s.once('error', reject);
    s.listen(0, '127.0.0.1', () => {
      const p = s.address().port;
      s.close(() => resolve(p));
    });
  });
}

test('owner gate fails closed for GET and unauthorized POST, without Atlassian access', async () => {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'mcp-owner-test-'));
  const port = await freePort();
  const url = 'http://127.0.0.1:' + port;
  const child = spawn(process.execPath, ['dist/server.js'], {
    cwd: new URL('..', import.meta.url).pathname,
    env: {
      ...process.env,
      PORT: String(port),
      NODE_ENV: 'test',
      MCP_PUBLIC_URL: url,
      ATLASSIAN_CLIENT_ID: 'test-client-id',
      ATLASSIAN_CLIENT_SECRET: 'test-atlassian-client-secret-with-length',
      ATLASSIAN_REDIRECT_URI: url + '/oauth/atlassian/callback',
      ATLASSIAN_SITE_URL: 'https://example.atlassian.net',
      OAUTH_STATE_PATH: path.join(directory, 'oauth-state.enc'),
      UPSTASH_REDIS_REST_URL: '',
      UPSTASH_REDIS_REST_TOKEN: '',
      MCP_OWNER_CONNECTION_SECRET: 'owner-connection-secret-with-strong-test-length'
    },
    stdio: 'ignore'
  });
  try {
    let ready = false;
    for (let i = 0; i < 100; i++) {
      if (child.exitCode !== null) throw new Error('MCP server exited before ready');
      try {
        const res = await fetch(url + '/health');
        if (res.ok) { ready = true; break; }
      } catch {}
      await new Promise(resolve => setTimeout(resolve, 50));
    }
    assert.equal(ready, true, 'MCP server should start with a configured owner secret');
    const query = new URLSearchParams({
      client_id: 'https://chatgpt.com/oauth/client.json',
      redirect_uri: 'https://chatgpt.com/connector_platform_oauth_redirect',
      resource: url,
      response_type: 'code',
      code_challenge_method: 'S256',
      code_challenge: 'A'.repeat(43),
      state: 'owner-test'
    });
    const get = await fetch(url + '/oauth/authorize?' + query);
    assert.equal(get.status, 200);
    const page = await get.text();
    assert.match(page, /connection_secret/);
    assert.match(page, /Owner connection secret/);
    for (const secret of ['', 'wrong-secret']) {
      const post = await fetch(url + '/oauth/authorize', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ ...Object.fromEntries(query), connection_secret: secret }),
        redirect: 'manual'
      });
      assert.equal(post.status, 403, 'unauthorized owner attempt must not redirect or issue code');
      assert.equal((await post.json()).error, 'access_denied');
    }
    const mcp = await fetch(url + '/mcp');
    assert.equal(mcp.status, 401);
  } finally {
    child.kill();
    await rm(directory, { recursive: true, force: true });
  }
});
