import type { SignerConfig, SignatureResult } from './types.js';
export declare function deriveSignerKey(masterSecret: string, signerIndex: number): string;
export declare function sign(contentHash: string, timestamp: Date, signerSecret: string): string;
export declare function verifyMultiSignature(contentHash: string, timestamp: Date, signature: string, signerSecret: string): boolean;
export declare function derivePublicKey(signerSecret: string): string;
export declare function createMultiSignatures(contentHash: string, signers: SignerConfig[]): SignatureResult[];
export declare function verifyMultiSignatures(contentHash: string, results: SignatureResult[], signers: SignerConfig[]): {
    valid: boolean;
    threshold: number;
    passed: number;
    failed: string[];
};
export declare function buildDefaultSigners(masterSecret: string): SignerConfig[];
//# sourceMappingURL=multisig.d.ts.map