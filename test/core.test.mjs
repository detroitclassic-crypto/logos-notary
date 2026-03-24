/**
 * Test suite — logos-notary core
 * Run: node --test test/core.test.mjs  (Node 18+)
 */

import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import {
  hashContent, generateNonce, generateProofId, signProof, verifySignature,
  createProof, verifyProof, verifyContentAgainstProof,
  buildMerkleTree, getMerklePath, verifyMerklePath, getProofInclusion,
  AuditChain, verifyAuditChain,
  createMultiSignatures, verifyMultiSignatures, buildDefaultSigners, verifyMultiSignature,
} from '../dist/index.js';

const SECRET = 'test-secret-32chars-minimum-length!!';

// ─── Core ─────────────────────────────────────────────────────────────────────

describe('hashContent', () => {
  it('produces consistent hash for strings', () => {
    const h1 = hashContent('hello world');
    const h2 = hashContent('hello world');
    assert.equal(h1, h2);
  });

  it('produces different hash for different input', () => {
    assert.notEqual(hashContent('a'), hashContent('b'));
  });

  it('hashes objects by JSON', () => {
    const h1 = hashContent({ x: 1, y: 2 });
    const h2 = hashContent({ x: 1, y: 2 });
    assert.equal(h1, h2);
  });

  it('hashes Buffers', () => {
    const buf = Buffer.from('binary data');
    assert.equal(hashContent(buf).length, 64);
  });

  it('returns 64-char hex string', () => {
    assert.match(hashContent('test'), /^[a-f0-9]{64}$/);
  });
});

describe('createProof + verifyProof', () => {
  it('creates a valid proof', () => {
    const proof = createProof('my document', { secret: SECRET, proofIdPrefix: 'TEST' });
    assert.ok(proof.proofId.startsWith('TEST-'));
    assert.equal(proof.algorithm, 'SHA256-HMAC');
    assert.ok(proof.contentHash.length === 64);
  });

  it('verifies its own proof', () => {
    const proof = createProof({ name: 'Alice', role: 'Admin' }, { secret: SECRET });
    const result = verifyProof(proof, SECRET);
    assert.equal(result.valid, true);
  });

  it('fails with wrong secret', () => {
    const proof = createProof('test', { secret: SECRET });
    const result = verifyProof(proof, 'wrong-secret');
    assert.equal(result.valid, false);
  });

  it('verifyContentAgainstProof passes for unchanged content', () => {
    const doc = { invoice: 'INV-001', amount: 500 };
    const proof = createProof(doc, { secret: SECRET });
    const result = verifyContentAgainstProof(doc, proof, SECRET);
    assert.equal(result.valid, true);
  });

  it('verifyContentAgainstProof fails for tampered content', () => {
    const doc = { invoice: 'INV-001', amount: 500 };
    const proof = createProof(doc, { secret: SECRET });
    const tampered = { invoice: 'INV-001', amount: 9999 };
    const result = verifyContentAgainstProof(tampered, proof, SECRET);
    assert.equal(result.valid, false);
    assert.match(result.message, /hash mismatch/);
  });

  it('includes verificationUrl when base url provided', () => {
    const proof = createProof('test', { secret: SECRET, verificationBaseUrl: 'https://example.com/verify' });
    assert.ok(proof.verificationUrl?.startsWith('https://example.com/verify/'));
  });
});

// ─── Merkle ───────────────────────────────────────────────────────────────────

describe('Merkle tree', () => {
  const hashes = Array.from({ length: 8 }, (_, i) => hashContent(`doc-${i}`));

  it('builds a tree with correct root', () => {
    const { root, tree } = buildMerkleTree(hashes);
    assert.equal(root.length, 64);
    assert.ok(tree.length > 1);
  });

  it('same leaves → same root', () => {
    const { root: r1 } = buildMerkleTree(hashes);
    const { root: r2 } = buildMerkleTree(hashes);
    assert.equal(r1, r2);
  });

  it('different leaves → different root', () => {
    const alt = [...hashes];
    alt[0] = hashContent('different');
    const { root: r1 } = buildMerkleTree(hashes);
    const { root: r2 } = buildMerkleTree(alt);
    assert.notEqual(r1, r2);
  });

  it('verifies all leaf paths', () => {
    const { root, tree } = buildMerkleTree(hashes);
    for (let i = 0; i < hashes.length; i++) {
      const path = getMerklePath(tree, i);
      assert.equal(verifyMerklePath(hashes[i], root, path), true, `Leaf ${i} path invalid`);
    }
  });

  it('rejects forged leaf', () => {
    const { root, tree } = buildMerkleTree(hashes);
    const forged = hashContent('forged');
    const path = getMerklePath(tree, 0);
    assert.equal(verifyMerklePath(forged, root, path), false);
  });

  it('getProofInclusion returns correct index', () => {
    const inclusion = getProofInclusion(hashes, hashes[3]);
    assert.ok(inclusion);
    assert.equal(inclusion.index, 3);
    assert.equal(verifyMerklePath(hashes[3], inclusion.root, inclusion.path), true);
  });

  it('returns null for unknown hash', () => {
    const result = getProofInclusion(hashes, hashContent('not-in-set'));
    assert.equal(result, null);
  });
});

// ─── Audit chain ──────────────────────────────────────────────────────────────

describe('AuditChain', () => {
  it('builds and verifies a clean chain', () => {
    const chain = new AuditChain();
    chain.append('login', undefined, undefined, { user: 'alice' });
    chain.append('upload', 'PROOF-001', 'abc123', { file: 'contract.pdf' });
    chain.append('sign', 'PROOF-001', 'abc123', { signedBy: 'alice' });
    const result = chain.verify();
    assert.equal(result.valid, true);
    assert.equal(result.entries, 3);
    assert.equal(result.errors.length, 0);
  });

  it('serializes and restores correctly', () => {
    const chain = new AuditChain();
    chain.append('event_a', undefined, undefined, { x: 1 });
    chain.append('event_b', undefined, undefined, { x: 2 });
    const restored = AuditChain.fromJSON(chain.toJSON());
    assert.equal(restored.verify().valid, true);
  });

  it('detects tampered entryHash', () => {
    const chain = new AuditChain();
    chain.append('login');
    chain.append('action');

    const entries = JSON.parse(chain.toJSON());
    entries[0].entryHash = 'aaaa' + 'b'.repeat(60);

    const tampered = AuditChain.fromJSON(JSON.stringify(entries));
    const result = tampered.verify();
    assert.equal(result.valid, false);
    assert.ok(result.errors.length > 0);
  });

  it('standalone verifyAuditChain works', () => {
    const chain = new AuditChain();
    chain.append('a');
    chain.append('b');
    const result = verifyAuditChain(chain.getEntries());
    assert.equal(result.valid, true);
  });
});

// ─── Multi-sig ────────────────────────────────────────────────────────────────

describe('Multi-signature', () => {
  const contentHash = hashContent('important document');
  const signers = buildDefaultSigners(SECRET);

  it('creates signatures for all signers', () => {
    const sigs = createMultiSignatures(contentHash, signers);
    assert.equal(sigs.length, 3);
    sigs.forEach(s => assert.equal(s.signature.length, 64));
  });

  it('verifies all signatures', () => {
    const sigs = createMultiSignatures(contentHash, signers);
    const result = verifyMultiSignatures(contentHash, sigs, signers);
    assert.equal(result.valid, true);
    assert.equal(result.passed, 3);
    assert.equal(result.failed.length, 0);
  });

  it('detects tampered signature', () => {
    const sigs = createMultiSignatures(contentHash, signers);
    sigs[1] = { ...sigs[1], signature: 'f'.repeat(64) };
    const result = verifyMultiSignatures(contentHash, sigs, signers);
    assert.equal(result.valid, false);
    assert.ok(result.failed.length > 0);
  });
});
