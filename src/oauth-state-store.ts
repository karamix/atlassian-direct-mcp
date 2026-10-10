import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import path from 'node:path';

export interface AtlassianTokenState {
  access_token: string;
  refresh_token?: string;
  expires_in?: number;
  scope?: string;
  expires_at: number;
}

export interface OAuthState {
  atlassianToken: AtlassianTokenState | null;
  accessTokens: Record<string, number>;
  refreshTokens: string[];
}

const emptyState = (): OAuthState => ({ atlassianToken: null, accessTokens: {}, refreshTokens: [] });

function cloneState(state: OAuthState): OAuthState {
  return {
    atlassianToken: state.atlassianToken ? { ...state.atlassianToken } : null,
    accessTokens: { ...state.accessTokens },
    refreshTokens: [...state.refreshTokens]
  };
}

function isOAuthState(value: unknown): value is OAuthState {
  if (!value || typeof value !== 'object') return false;
  const state = value as Partial<OAuthState>;
  if (!state.accessTokens || typeof state.accessTokens !== 'object' || Array.isArray(state.accessTokens)) return false;
  if (!Array.isArray(state.refreshTokens) || !state.refreshTokens.every(token => typeof token === 'string')) return false;
  if (!Object.prototype.hasOwnProperty.call(state, 'atlassianToken')) return false;
  if (state.atlassianToken !== null) {
    const token = state.atlassianToken as Partial<AtlassianTokenState>;
    if (typeof token.access_token !== 'string' || typeof token.expires_at !== 'number') return false;
    if (token.refresh_token !== undefined && typeof token.refresh_token !== 'string') return false;
  }
  return Object.entries(state.accessTokens).every(([token, expiresAt]) => token.length > 0 && typeof expiresAt === 'number');
}

export class OAuthStateStore {
  private state = emptyState();
  private writeQueue: Promise<void> = Promise.resolve();
  private readonly encryptionKey: Buffer;

  constructor(private readonly filePath: string, clientSecret: string) {
    if (!filePath) throw new Error('OAuth state path is required');
    if (!clientSecret) throw new Error('Atlassian client secret is required to protect OAuth state');
    this.encryptionKey = crypto.createHmac('sha256', clientSecret).update('kostas-atlassian-direct/oauth-state/v1').digest();
  }

  snapshot(): OAuthState {
    return cloneState(this.state);
  }

  async load(): Promise<void> {
    let contents: string;
    try {
      contents = await fs.readFile(this.filePath, 'utf8');
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') {
        this.state = emptyState();
        return;
      }
      throw error;
    }

    const envelope = JSON.parse(contents) as { version?: number; iv?: string; tag?: string; ciphertext?: string };
    if (envelope.version !== 1 || !envelope.iv || !envelope.tag || !envelope.ciphertext) {
      throw new Error('OAuth state file has an unsupported or invalid format');
    }

    try {
      const decipher = crypto.createDecipheriv('aes-256-gcm', this.encryptionKey, Buffer.from(envelope.iv, 'base64'));
      decipher.setAuthTag(Buffer.from(envelope.tag, 'base64'));
      const plaintext = Buffer.concat([
        decipher.update(Buffer.from(envelope.ciphertext, 'base64')),
        decipher.final()
      ]).toString('utf8');
      const restored: unknown = JSON.parse(plaintext);
      if (!isOAuthState(restored)) throw new Error('OAuth state file contains invalid data');
      this.state = restored;
    } catch (error) {
      if (error instanceof Error && error.message === 'OAuth state file contains invalid data') throw error;
      throw new Error('OAuth state file could not be decrypted; keep the Atlassian client secret stable or reauthorize after rotating it');
    }
  }

  async update<T>(mutate: (state: OAuthState) => T): Promise<T> {
    const operation = this.writeQueue.then(async () => {
      const next = cloneState(this.state);
      const result = mutate(next);
      await this.persist(next);
      this.state = next;
      return result;
    });
    this.writeQueue = operation.then(() => undefined, () => undefined);
    return operation;
  }

  private async persist(state: OAuthState): Promise<void> {
    const directory = path.dirname(this.filePath);
    await fs.mkdir(directory, { recursive: true, mode: 0o700 });
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', this.encryptionKey, iv);
    const ciphertext = Buffer.concat([
      cipher.update(JSON.stringify(state), 'utf8'),
      cipher.final()
    ]);
    const envelope = JSON.stringify({
      version: 1,
      iv: iv.toString('base64'),
      tag: cipher.getAuthTag().toString('base64'),
      ciphertext: ciphertext.toString('base64')
    });
    const temporaryPath = `${this.filePath}.${process.pid}.${crypto.randomUUID()}.tmp`;
    await fs.writeFile(temporaryPath, envelope, { encoding: 'utf8', mode: 0o600 });
    await fs.rename(temporaryPath, this.filePath);
    await fs.chmod(this.filePath, 0o600);
  }
}
