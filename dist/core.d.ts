import type { CreateProofResult, VerifyResult, ProofRecord, NotaryOptions } from './types.js';
export declare function hashContent(content: string | object | Buffer): string;
export declare function generateNonce(): string;
export declare function generateProofId(prefix?: string, sequenceNumber?: number): string;
export declare function signProof(contentHash: string, timestamp: Date, nonce: string, secret: string): string;
export declare function verifySignature(contentHash: string, timestamp: Date, nonce: string, signature: string, secret: string): boolean;
export declare function createProof(content: string | object | Buffer, options: NotaryOptions, sequenceNumber?: number): CreateProofResult;
export declare function verifyProof(proof: ProofRecord, secret: string): VerifyResult;
export declare function verifyContentAgainstProof(content: string | object | Buffer, proof: ProofRecord, secret: string): VerifyResult;
//# sourceMappingURL=core.d.ts.map