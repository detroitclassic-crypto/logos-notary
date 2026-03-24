import crypto from 'crypto';
import type { SignerConfig, SignatureResult } from './types.js';

export function deriveSignerKey(masterSecret: string, signerIndex: number): string {
  return crypto
    .createHash('sha256')
    .update(`${masterSecret}-signer-${signerIndex}`)
    .digest('hex');
}

export function sign(
  contentHash: string,
  timestamp: Date,
  signerSecret: string
): string {
  const data = `${contentHash}|${timestamp.toISOString()}|${signerSecret}`;
  return crypto.createHmac('sha256', signerSecret).update(data).digest('hex');
}

export function verifyMultiSignature(
  contentHash: string,
  timestamp: Date,
  signature: string,
  signerSecret: string
): boolean {
  const expected = sign(contentHash, timestamp, signerSecret);
  try {
    return crypto.timingSafeEqual(
      Buffer.from(signature, 'hex'),
      Buffer.from(expected, 'hex')
    );
  } catch {
    return false;
  }
}

export function derivePublicKey(signerSecret: string): string {
  return crypto.createHash('sha256').update(signerSecret).digest('hex');
}

export function createMultiSignatures(
  contentHash: string,
  signers: SignerConfig[]
): SignatureResult[] {
  const now = new Date();

  return signers.map(signer => ({
    signerName: signer.name,
    signerType: signer.type,
    signature: sign(contentHash, now, signer.secret),
    signedAt: now,
  }));
}

export function verifyMultiSignatures(
  contentHash: string,
  results: SignatureResult[],
  signers: SignerConfig[]
): { valid: boolean; threshold: number; passed: number; failed: string[] } {
  const failed: string[] = [];

  for (const result of results) {
    const signer = signers.find(s => s.name === result.signerName);
    if (!signer) {
      failed.push(`${result.signerName}: signer config not found`);
      continue;
    }

    const ok = verifyMultiSignature(contentHash, result.signedAt, result.signature, signer.secret);
    if (!ok) failed.push(`${result.signerName}: signature invalid`);
  }

  return {
    valid: failed.length === 0,
    threshold: results.length,
    passed: results.length - failed.length,
    failed,
  };
}

export function buildDefaultSigners(masterSecret: string): SignerConfig[] {
  return [
    { name: 'primary', type: 'internal', secret: deriveSignerKey(masterSecret, 1) },
    { name: 'secondary', type: 'internal', secret: deriveSignerKey(masterSecret, 2) },
    { name: 'witness', type: 'autonomous', secret: deriveSignerKey(masterSecret, 3) },
  ];
}
