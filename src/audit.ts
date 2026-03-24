import crypto from 'crypto';
import type { AuditEntry, AuditIntegrityResult } from './types.js';

function stableStringify(obj: unknown): string {
  if (obj === null || obj === undefined) return 'null';
  if (typeof obj !== 'object') return JSON.stringify(obj);
  if (Array.isArray(obj)) return '[' + (obj as unknown[]).map(stableStringify).join(',') + ']';
  const keys = Object.keys(obj as object).sort();
  return '{' + keys.map(k => `"${k}":${stableStringify((obj as Record<string, unknown>)[k])}`).join(',') + '}';
}

export function computeEntryHash(
  eventType: string,
  proofId: string | null,
  contentHash: string | null,
  eventData: Record<string, unknown>,
  previousHash: string | null,
  occurredAt: Date | string
): string {
  const timestamp =
    typeof occurredAt === 'string'
      ? new Date(occurredAt).getTime()
      : occurredAt.getTime();

  const data = stableStringify({
    contentHash,
    eventData: eventData ?? {},
    eventType,
    previousHash,
    timestamp,
  });

  return crypto.createHash('sha256').update(data).digest('hex');
}

export function createAuditEntry(
  eventType: string,
  sequenceNumber: number,
  previousHash: string | null,
  proofId?: string,
  contentHash?: string,
  eventData?: Record<string, unknown>
): AuditEntry {
  const occurredAt = new Date();
  const entryHash = computeEntryHash(
    eventType,
    proofId ?? null,
    contentHash ?? null,
    eventData ?? {},
    previousHash,
    occurredAt
  );

  return {
    sequenceNumber,
    eventType,
    proofId,
    contentHash,
    eventData,
    entryHash,
    previousHash,
    occurredAt,
  };
}

export function verifyAuditChain(entries: AuditEntry[]): AuditIntegrityResult {
  const errors: string[] = [];

  if (entries.length === 0) {
    return { valid: true, entries: 0, errors: [] };
  }

  const sorted = [...entries].sort((a, b) => a.sequenceNumber - b.sequenceNumber);

  for (let i = 0; i < sorted.length; i++) {
    const entry = sorted[i];

    if (i === 0 && entry.previousHash !== null) {
      errors.push(`Entry ${entry.sequenceNumber}: First entry must have null previousHash`);
    }

    if (i > 0 && entry.previousHash !== sorted[i - 1].entryHash) {
      errors.push(
        `Entry ${entry.sequenceNumber}: Hash chain broken — previousHash does not match entry ${sorted[i - 1].sequenceNumber}`
      );
    }

    const expectedHash = computeEntryHash(
      entry.eventType,
      entry.proofId ?? null,
      entry.contentHash ?? null,
      entry.eventData ?? {},
      entry.previousHash,
      entry.occurredAt
    );

    if (entry.entryHash !== expectedHash) {
      errors.push(`Entry ${entry.sequenceNumber}: entryHash mismatch — entry may have been tampered with`);
    }
  }

  return {
    valid: errors.length === 0,
    entries: sorted.length,
    errors,
  };
}

export class AuditChain {
  private entries: AuditEntry[] = [];

  append(
    eventType: string,
    proofId?: string,
    contentHash?: string,
    eventData?: Record<string, unknown>
  ): AuditEntry {
    const previousHash = this.entries.length > 0
      ? this.entries[this.entries.length - 1].entryHash
      : null;

    const entry = createAuditEntry(
      eventType,
      this.entries.length + 1,
      previousHash,
      proofId,
      contentHash,
      eventData
    );

    this.entries.push(entry);
    return entry;
  }

  verify(): AuditIntegrityResult {
    return verifyAuditChain(this.entries);
  }

  getEntries(): AuditEntry[] {
    return [...this.entries];
  }

  toJSON(): string {
    return JSON.stringify(this.entries, null, 2);
  }

  static fromJSON(json: string): AuditChain {
    const chain = new AuditChain();
    const parsed = JSON.parse(json) as AuditEntry[];
    chain.entries = parsed.map(e => ({
      ...e,
      occurredAt: new Date(e.occurredAt),
    }));
    return chain;
  }
}
