import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { OAuthStateStore } from '../dist/oauth-state-store.js';

const clientSecret = 'test-client-secret-with-enough-entropy';

test('encrypted OAuth state survives store reloads', async () => {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'atlassian-oauth-state-'));
  const filePath = path.join(directory, 'oauth-state.enc');
  try {
    const first = new OAuthStateStore(filePath, clientSecret);
    await first.load();
    await first.update(state => {
      state.atlassianToken = {
        access_token: 'atlassian-access-secret',
        refresh_token: 'atlassian-refresh-secret',
        expires_at: 1234567890
      };
      state.accessTokens['chatgpt-access-secret'] = 1234567890;
      state.refreshTokens.push('chatgpt-refresh-secret');
    });

    const file = await readFile(filePath, 'utf8');
    assert.equal(file.includes('atlassian-refresh-secret'), false);
    assert.equal(file.includes('chatgpt-refresh-secret'), false);

    const restored = new OAuthStateStore(filePath, clientSecret);
    await restored.load();
    assert.deepEqual(restored.snapshot(), first.snapshot());
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test('serializes concurrent updates and rejects state encrypted with another client secret', async () => {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'atlassian-oauth-state-'));
  const filePath = path.join(directory, 'oauth-state.enc');
  try {
    const store = new OAuthStateStore(filePath, clientSecret);
    await store.load();
    await Promise.all(Array.from({ length: 8 }, (_, index) =>
      store.update(state => {
        state.accessTokens[`access-${index}`] = index + 1;
        state.refreshTokens.push(`refresh-${index}`);
      })
    ));
    assert.equal(Object.keys(store.snapshot().accessTokens).length, 8);
    assert.equal(store.snapshot().refreshTokens.length, 8);

    const wrongKey = new OAuthStateStore(filePath, 'different-client-secret');
    await assert.rejects(wrongKey.load(), /could not be decrypted/);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
