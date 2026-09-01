import { describe, expect, it } from 'vitest';
import { generateKeyPairSync, sign as edSign } from 'node:crypto';
import { Guard } from '../src/guard.js';

const { publicKey, privateKey } = generateKeyPairSync('ed25519');
const publicKeyPem = publicKey.export({ type: 'spki', format: 'pem' }).toString();
const privateKeyPem = privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();

function mintOffline(orgId: string, plan: string, expiresAt: number): string {
  const payload = Buffer.from(
    JSON.stringify({ orgId, plan, iat: Math.floor(Date.now() / 1000), exp: Math.floor(expiresAt / 1000) }),
    'utf8',
  ).toString('base64url');
  const signed = `sagoff.v1.${payload}`;
  const sig = edSign(null, Buffer.from(signed, 'utf8'), privateKeyPem).toString('base64url');
  return `${signed}.${sig}`;
}

describe('SDK air-gapped offline licence', () => {
  it('activates from a valid offline licence with no control-plane URL', async () => {
    const token = mintOffline('org_1', 'ENTERPRISE', Date.now() + 86_400_000);
    const guard = await Guard.create({
      licenseKey: 'unused-in-offline',
      serverId: 'srv_air',
      offlineLicense: token,
      offlineLicensePublicKey: publicKeyPem,
      // no controlPlaneUrl reachable — must not matter
    });
    expect(guard.licenseState).toBe('active');
    expect(guard.planTier).toBe('ENTERPRISE');
    guard.close();
  });

  it('is invalid for an expired offline licence', async () => {
    const token = mintOffline('org_1', 'TEAM', Date.now() - 1000);
    const guard = await Guard.create({
      licenseKey: 'x',
      serverId: 'srv_air',
      offlineLicense: token,
      offlineLicensePublicKey: publicKeyPem,
      failOpenOnInvalidLicense: false,
    });
    expect(guard.licenseState).toBe('invalid');
    guard.close();
  });
});
