/**
 * Example 2 — Merkle tree batch verification
 *
 * Batch thousands of proofs into a single Merkle root.
 * Prove that any individual record is part of the batch
 * without revealing the other records — just the path.
 *
 * Use case: Notarize 1,000 invoices → publish ONE root hash → any invoice
 * can independently prove it was in that batch.
 */

import {
  hashContent,
  buildMerkleTree,
  getMerklePath,
  verifyMerklePath,
  getProofInclusion,
  verifyBatchInclusion,
} from '../dist/index.js';

// ─── 1. Hash 10 documents ────────────────────────────────────────────────────

const documents = Array.from({ length: 10 }, (_, i) => ({
  invoiceId: `INV-${String(i + 1).padStart(4, '0')}`,
  amount: (Math.random() * 10000).toFixed(2),
  issuedAt: new Date().toISOString(),
}));

const hashes = documents.map(d => hashContent(d));
console.log('\n📋 Documents hashed:', hashes.length);

// ─── 2. Build the Merkle tree ────────────────────────────────────────────────

const { root, tree } = buildMerkleTree(hashes);
console.log('\n🌳 Merkle root (publish this):', root);
console.log('   Tree depth:', tree.length, 'levels');

// ─── 3. Get proof-of-inclusion for document #4 ───────────────────────────────

const targetIndex = 3;
const targetHash = hashes[targetIndex];
const path = getMerklePath(tree, targetIndex);

console.log('\n🔍 Proof-of-inclusion for invoice', documents[targetIndex].invoiceId);
console.log('   Hash :', targetHash.substring(0, 20) + '...');
console.log('   Path :', path.path.length, 'steps');

// ─── 4. Verify the inclusion ─────────────────────────────────────────────────

const valid = verifyMerklePath(targetHash, root, path);
console.log('   Valid:', valid ? '✅ Confirmed in batch' : '❌ Not in batch');

// ─── 5. Convenience: getProofInclusion (builds tree + returns path) ──────────

const inclusion = getProofInclusion(hashes, hashes[7]);
console.log('\n📑 Auto-inclusion for invoice 8:', inclusion?.valid ? '✅' : '❌');
console.log('   Root matches:', inclusion?.root === root ? '✅' : '❌');

// ─── 6. Simulate a forged hash ────────────────────────────────────────────────

const forgedHash = hashContent({ ...documents[3], amount: '99999.00' });
const forgedCheck = verifyBatchInclusion(forgedHash, root, path);
console.log('\n🚨 Forged document in batch?', forgedCheck ? '❌ Should not happen' : '✅ Correctly rejected');
