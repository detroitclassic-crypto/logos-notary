export interface ProofRecord {
  proofId: string;
  contentHash: string;
  signatureHash: string;
  serverNonce: string;
  timestampedAt: Date;
  algorithm: string;
  verificationUrl?: string;
  qrData?: string;
}

export interface VerifyResult {
  valid: boolean;
  message: string;
  verifiedAt: Date;
  proof?: ProofRecord;
}

export interface MerkleTree {
  root: string;
  leaves: string[];
  tree: string[][];
}

export interface MerklePath {
  path: string[];
  positions: ('left' | 'right')[];
}

export interface MerkleProof {
  valid: boolean;
  root: string;
  index: number;
  path: MerklePath;
}

export interface AuditEntry {
  sequenceNumber: number;
  eventType: string;
  proofId?: string;
  contentHash?: string;
  eventData?: Record<string, unknown>;
  entryHash: string;
  previousHash: string | null;
  occurredAt: Date;
}

export interface SignerConfig {
  name: string;
  type: string;
  secret: string;
}

export interface SignatureResult {
  signerName: string;
  signerType: string;
  signature: string;
  signedAt: Date;
}

export interface NotaryOptions {
  secret: string;
  verificationBaseUrl?: string;
  proofIdPrefix?: string;
  includeQr?: boolean;
}

export interface CreateProofResult {
  proofId: string;
  contentHash: string;
  signatureHash: string;
  serverNonce: string;
  timestampedAt: Date;
  algorithm: string;
  verificationUrl?: string;
  qrData?: string;
}

export interface AuditIntegrityResult {
  valid: boolean;
  entries: number;
  errors: string[];
}
