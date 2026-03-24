/**
 * Example 1 — Basic document proof
 *
 * Create a cryptographic proof of existence for any content.
 * Store the result yourself (database, file, S3 — your choice).
 * Later, verify the content hasn't changed using the stored proof.
 */

import { createProof, verifyProof, verifyContentAgainstProof, hashContent } from '../dist/index.js';

const SECRET = process.env.NOTARY_SECRET || 'replace-this-with-a-32-char-secret!!';

// ─── 1. Notarize a document ───────────────────────────────────────────────────

const document = {
  title: 'Service Agreement v1.2',
  parties: ['Acme Corp', 'Buyer LLC'],
  signedAt: '2026-03-21T10:00:00Z',
  terms: 'Payment net-30. Deliverables as per SOW attached.',
};

const proof = createProof(document, {
  secret: SECRET,
  verificationBaseUrl: 'https://yourapp.com/verify',
  proofIdPrefix: 'DOC',
});

console.log('\n✅ Proof created:');
console.log('  Proof ID     :', proof.proofId);
console.log('  Content Hash :', proof.contentHash);
console.log('  Signature    :', proof.signatureHash.substring(0, 20) + '...');
console.log('  Timestamp    :', proof.timestampedAt.toISOString());
console.log('  Verify URL   :', proof.verificationUrl);

// ─── 2. Persist the proof (here we just keep it in memory) ───────────────────

const storedProof = {
  proofId: proof.proofId,
  contentHash: proof.contentHash,
  signatureHash: proof.signatureHash,
  serverNonce: proof.serverNonce,
  timestampedAt: proof.timestampedAt,
  algorithm: proof.algorithm,
};

// ─── 3. Later — verify the stored proof is still valid ───────────────────────

const result = verifyProof(storedProof, SECRET);
console.log('\n🔍 Verification result:', result.valid ? '✅ VALID' : '❌ INVALID');
console.log('  Message:', result.message);

// ─── 4. Verify the original content matches the proof ────────────────────────

const contentCheck = verifyContentAgainstProof(document, storedProof, SECRET);
console.log('\n📄 Content integrity:', contentCheck.valid ? '✅ UNCHANGED' : '❌ MISMATCH');

// ─── 5. Simulate tampering ────────────────────────────────────────────────────

const tamperedDocument = { ...document, terms: 'Payment net-90.' };
const tamperedCheck = verifyContentAgainstProof(tamperedDocument, storedProof, SECRET);
console.log('\n🚨 Tampered content:', tamperedCheck.valid ? '✅ UNCHANGED' : '❌ ' + tamperedCheck.message);

// ─── 6. Hash a file buffer (e.g. PDF, image) ─────────────────────────────────

const fileBuffer = Buffer.from('PDF content here...');
const fileHash = hashContent(fileBuffer);
console.log('\n📁 File hash:', fileHash);
