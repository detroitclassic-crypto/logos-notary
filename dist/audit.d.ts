import type { AuditEntry, AuditIntegrityResult } from './types.js';
export declare function computeEntryHash(eventType: string, proofId: string | null, contentHash: string | null, eventData: Record<string, unknown>, previousHash: string | null, occurredAt: Date | string): string;
export declare function createAuditEntry(eventType: string, sequenceNumber: number, previousHash: string | null, proofId?: string, contentHash?: string, eventData?: Record<string, unknown>): AuditEntry;
export declare function verifyAuditChain(entries: AuditEntry[]): AuditIntegrityResult;
export declare class AuditChain {
    private entries;
    append(eventType: string, proofId?: string, contentHash?: string, eventData?: Record<string, unknown>): AuditEntry;
    verify(): AuditIntegrityResult;
    getEntries(): AuditEntry[];
    toJSON(): string;
    static fromJSON(json: string): AuditChain;
}
//# sourceMappingURL=audit.d.ts.map