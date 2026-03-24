/**
 * Example 3 — Immutable audit chain
 *
 * Every event is chained to the previous via its SHA-256 hash.
 * Tampering with any entry invalidates all subsequent entries.
 * Serialize to JSON, persist anywhere, restore and verify integrity.
 *
 * Use case: Compliance audit trail, access logs, trade records,
 * medical record change history — any sequence of events where
 * "did this happen, in this order, unmodified?" must be provable.
 */

import { AuditChain, verifyAuditChain } from '../dist/index.js';

// ─── 1. Build an audit chain in memory ───────────────────────────────────────

const chain = new AuditChain();

chain.append('user_login',   undefined, undefined, { userId: 'user_42', ip: '192.168.1.1' });
chain.append('document_uploaded', 'DOC-00001', 'abc123...', { filename: 'contract.pdf', size: 84320 });
chain.append('document_signed',   'DOC-00001', 'abc123...', { signedBy: 'alice@acme.com' });
chain.append('document_shared',   'DOC-00001', 'abc123...', { sharedWith: 'bob@buyer.com' });
chain.append('user_logout',  undefined, undefined, { userId: 'user_42' });

console.log('\n📜 Audit chain — entries:', chain.getEntries().length);

// ─── 2. Verify integrity ──────────────────────────────────────────────────────

const result = chain.verify();
console.log('\n🔍 Chain integrity:', result.valid ? '✅ VALID' : '❌ BROKEN');
console.log('   Entries verified:', result.entries);

// ─── 3. Serialize → persist → restore → re-verify ────────────────────────────

const serialized = chain.toJSON();
const restored = AuditChain.fromJSON(serialized);
const restoredResult = restored.verify();
console.log('\n💾 Restored from JSON:', restoredResult.valid ? '✅ VALID' : '❌ BROKEN');

// ─── 4. Simulate tampering ────────────────────────────────────────────────────

const entries = JSON.parse(serialized);
entries[2].eventData = { signedBy: 'hacker@evil.com' };
entries[2].entryHash = 'fakehash000';

const tamperedChain = AuditChain.fromJSON(JSON.stringify(entries));
const tamperedResult = tamperedChain.verify();

console.log('\n🚨 Tampered chain:', tamperedResult.valid ? '✅ No tamper detected' : '❌ Tampering detected!');
console.log('   Errors:');
tamperedResult.errors.forEach(e => console.log('   -', e));

// ─── 5. Standalone verify (pass entries from your DB) ────────────────────────

const rawEntries = chain.getEntries();
const standaloneResult = verifyAuditChain(rawEntries);
console.log('\n📋 Standalone verify:', standaloneResult.valid ? '✅ VALID' : '❌ BROKEN');
