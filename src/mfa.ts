import { createHmac, randomBytes } from 'node:crypto';

export interface MfaSecretStore {
  encrypt(secret: string): Promise<string>;
  decrypt(ciphertext: string): Promise<string>;
}

/** AES-256-GCM store. The key is supplied by a secret manager/environment, never by a user. */
export class EncryptedMfaSecretStore implements MfaSecretStore {
  private readonly key: Buffer;
  constructor(encodedKey = process.env.MFA_ENCRYPTION_KEY) {
    if (!encodedKey) throw new Error('MFA_ENCRYPTION_KEY_REQUIRED');
    const key = /^[0-9a-f]{64}$/i.test(encodedKey) ? Buffer.from(encodedKey, 'hex') : Buffer.from(encodedKey, 'base64');
    if (key.length !== 32) throw new Error('MFA_ENCRYPTION_KEY_INVALID');
    this.key = key;
  }
  async encrypt(secret: string): Promise<string> {
    const iv = randomBytes(12); const cipher = await import('node:crypto').then(x => x.createCipheriv('aes-256-gcm', this.key, iv));
    const body = Buffer.concat([cipher.update(secret, 'utf8'), cipher.final()]);
    return [iv, cipher.getAuthTag(), body].map(x => x.toString('base64url')).join('.');
  }
  async decrypt(value: string): Promise<string> {
    try {
      // Buffer.from(..., 'base64url') is deliberately permissive: non-canonical
      // trailing bits can be changed without changing the decoded bytes. Decode
      // and re-encode each component so every textual mutation is rejected.
      const parts = value.split('.');
      if (parts.length !== 3) throw new Error();
      const iv = decodeCanonicalBase64url(parts[0]);
      const tag = decodeCanonicalBase64url(parts[1]);
      const body = decodeCanonicalBase64url(parts[2]);
      if (iv.length !== 12 || tag.length !== 16) throw new Error();
      const decipher = await import('node:crypto').then(x => x.createDecipheriv('aes-256-gcm', this.key, iv));
      decipher.setAuthTag(tag);
      return Buffer.concat([decipher.update(body), decipher.final()]).toString('utf8');
    } catch { throw new Error('MFA_SECRET_DECRYPT_FAILED'); }
  }
}

export interface MfaEnrollment { secret: string; otpauthUri: string }
export function createTotpEnrollment(account: string, issuer = 'StempelPass Deutschland'): MfaEnrollment {
  const secret = base32Encode(randomBytes(20));
  return { secret, otpauthUri: `otpauth://totp/${encodeURIComponent(issuer)}:${encodeURIComponent(account)}?secret=${secret}&issuer=${encodeURIComponent(issuer)}&algorithm=SHA1&digits=6&period=30` };
}
export function verifyTotp(secret: string, code: string, at = Date.now()): boolean {
  if (!/^\d{6}$/.test(code)) return false;
  let key: Buffer; try { key = base32Decode(secret); } catch { return false; }
  const counter = Math.floor(at / 1000 / 30);
  for (let offset = -1; offset <= 1; offset++) { const b = Buffer.alloc(8); b.writeBigUInt64BE(BigInt(counter + offset)); const digest = createHmac('sha1', key).update(b).digest(); const pos = digest[19] & 15; const value = ((digest[pos] & 127) << 24) | ((digest[pos + 1] & 255) << 16) | ((digest[pos + 2] & 255) << 8) | (digest[pos + 3] & 255); if (String(value % 1_000_000).padStart(6, '0') === code) return true; }
  return false;
}
function decodeCanonicalBase64url(value: string): Buffer {
  if (!value || !/^[A-Za-z0-9_-]+$/.test(value) || value.length % 4 === 1) throw new Error();
  const decoded = Buffer.from(value, 'base64url');
  if (decoded.toString('base64url') !== value) throw new Error();
  return decoded;
}
function base32Encode(input: Buffer): string { const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'; let bits = 0, value = 0, out = ''; for (const byte of input) { value = (value << 8) | byte; bits += 8; while (bits >= 5) { out += alphabet[(value >>> (bits - 5)) & 31]; bits -= 5; } } if (bits) out += alphabet[(value << (5 - bits)) & 31]; return out; }
function base32Decode(input: string): Buffer { const clean = input.toUpperCase().replace(/=+$/, ''); let bits = 0, value = 0; const out: number[] = []; for (const c of clean) { const n = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'.indexOf(c); if (n < 0) throw new Error(); value = (value << 5) | n; bits += 5; if (bits >= 8) { out.push((value >>> (bits - 8)) & 255); bits -= 8; } } return Buffer.from(out); }
