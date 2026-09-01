/**
 * Offline / air-gapped licence verification.
 *
 * A hosted deployment validates a licence by calling the control plane. A server
 * that cannot reach the control plane at all — an air-gapped or strictly
 * network-isolated deployment, common in regulated buyers — needs a licence it
 * can verify locally. The control plane signs a compact token with an Ed25519
 * private key; the SDK verifies it here with the matching public key, entirely
 * offline. No secret is embedded: the public key only verifies, it cannot mint.
 *
 * Token format (all base64url, `.`-joined):
 *   sagoff.v1.<payload>.<signature>
 * where payload is JSON `{ orgId, plan, iat, exp }` (exp in unix seconds) and the
 * signature is Ed25519 over the exact bytes `sagoff.v1.<payload>`.
 */

import { verify as edVerify } from 'node:crypto';

export interface OfflineLicense {
  orgId: string;
  plan: 'FREE' | 'PRO' | 'TEAM' | 'ENTERPRISE';
  /** Expiry, unix milliseconds. */
  expiresAt: number;
}

export const OFFLINE_PREFIX = 'sagoff.v1';

function b64urlToBuf(s: string): Buffer {
  return Buffer.from(s, 'base64url');
}

/**
 * Verify a signed offline licence. Returns the licence when the signature is
 * valid AND it has not expired, otherwise null. Never throws on malformed input.
 */
export function verifyOfflineLicense(
  token: string,
  publicKeyPem: string,
  nowMs: number = Date.now(),
): OfflineLicense | null {
  try {
    const parts = token.trim().split('.');
    // sagoff . v1 . payload . sig  →  4 segments
    if (parts.length !== 4 || `${parts[0]}.${parts[1]}` !== OFFLINE_PREFIX) return null;
    const signed = `${OFFLINE_PREFIX}.${parts[2]}`;
    const sig = b64urlToBuf(parts[3]);
    if (!edVerify(null, Buffer.from(signed, 'utf8'), publicKeyPem, sig)) return null;

    const payload = JSON.parse(b64urlToBuf(parts[2]).toString('utf8')) as {
      orgId?: unknown;
      plan?: unknown;
      exp?: unknown;
    };
    if (typeof payload.orgId !== 'string' || !payload.orgId) return null;
    if (payload.plan !== 'FREE' && payload.plan !== 'PRO' && payload.plan !== 'TEAM' && payload.plan !== 'ENTERPRISE') return null;
    if (typeof payload.exp !== 'number') return null;
    const expiresAt = payload.exp * 1000;
    if (nowMs >= expiresAt) return null;

    return { orgId: payload.orgId, plan: payload.plan, expiresAt };
  } catch {
    return null;
  }
}
