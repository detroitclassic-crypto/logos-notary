# logos-notary

**Waterproof cryptographic proof-of-existence for any content.**  
SHA-256 + HMAC document notarization with Merkle tree batching, hash-chained audit logs, and multi-signature verification.

[![npm version](https://img.shields.io/npm/v/logos-notary.svg)](https://www.npmjs.com/package/logos-notary)
[![license](https://img.shields.io/npm/l/logos-notary.svg)](./LICENSE)
[![zero dependencies](https://img.shields.io/badge/dependencies-zero-brightgreen)](./package.json)
[![Node.js](https://img.shields.io/badge/node-%3E%3D18-blue)](https://nodejs.org)
[![924 proofs in production](https://img.shields.io/badge/production%20proofs-924-purple)](https://logos257.com/verify)

> Built by [Grace AI Technologies LLC](https://logos257.com) — powering the LOGOS VPH-257 verification layer.  
> **924 real proofs verified in production.** This is not a demo.

---

## Why

Every developer eventually needs to answer: *"Can I prove this document existed, unmodified, at this exact moment?"*

- Law: *Did the contract predate the dispute?*
- Finance: *Was this transaction record altered after submission?*
- Healthcare: *Has this patient record been tampered with?*
- IP: *When did I create this design, before or after theirs?*

`logos-notary` answers all of these with nothing but mathematics.  
No blockchain fees. No third-party dependency. No trusted intermediary.  
Just SHA-256, HMAC, and your own secret key.

---

## Features

| Feature | Description |
|---|---|
| **Proof creation** | SHA-256 content hash + HMAC signature + nonce + timestamp |
| **Tamper detection** | Timing-safe signature verification catches any modification |
| **Merkle batching** | Batch thousands of proofs into one root hash — prove individual inclusion without exposing others |
| **Hash-chained audit log** | Every event chained to the previous; any tampering breaks all subsequent entries |
| **Multi-signature** | 3-signer system with derived keys from a master secret |
| **File hashing** | Buffer support for PDFs, images, any binary format |
| **Zero dependencies** | Uses only Node.js built-in `crypto` — nothing to audit, nothing to update |
| **Full TypeScript** | Complete type definitions included |

---

## Install

```bash
npm install logos-notary
```

Requires Node.js 18+.

---

## Quick start

```typescript
import { createProof, verifyProof, verifyContentAgainstProof } from 'logos-notary';

const SECRET = process.env.NOTARY_SECRET; // min 32 chars

// 1. Create a proof
const proof = createProof(
  { contract: 'MSA v1.2', signedBy: 'Alice', at: '2026-03-21' },
  { secret: SECRET, verificationBaseUrl: 'https://yourapp.com/verify' }
);

console.log(proof.proofId);       // PROOF-00001-AB3FC2
console.log(proof.contentHash);   // sha256 hex
console.log(proof.verificationUrl); // https://yourapp.com/verify/PROOF-00001-AB3FC2

// 2. Persist proof to your DB / file / S3 — your choice

// 3. Later: verify the stored proof is still valid
const check = verifyProof(storedProof, SECRET);
console.log(check.valid); // true

// 4. Verify the original content matches
const contentCheck = verifyContentAgainstProof(originalDocument, storedProof, SECRET);
console.log(contentCheck.valid);    // true  — content unchanged
console.log(contentCheck.message);  // "Proof is valid..."
```

---

## API Reference

### Core

#### `hashContent(content: string | object | Buffer): string`
Produces a SHA-256 hex digest. Accepts strings, JSON-serializable objects, or raw Buffers (for files).

#### `createProof(content, options, sequenceNumber?): CreateProofResult`
Creates a signed proof for any content.

```typescript
const proof = createProof(document, {
  secret: 'your-32-char-secret',
  verificationBaseUrl: 'https://yourapp.com/verify', // optional
  proofIdPrefix: 'DOC',    // optional, default 'PROOF'
  includeQr: true,         // optional, default true
});
// Returns: { proofId, contentHash, signatureHash, serverNonce, timestampedAt, algorithm, verificationUrl, qrData }
```

#### `verifyProof(proof: ProofRecord, secret: string): VerifyResult`
Verifies the HMAC signature on a stored proof.

#### `verifyContentAgainstProof(content, proof, secret): VerifyResult`
Checks that content still matches the original hash AND the signature is valid.

---

### Merkle tree

```typescript
import { buildMerkleTree, getMerklePath, verifyMerklePath, getProofInclusion } from 'logos-notary';

// Build from an array of SHA-256 hashes
const { root, tree } = buildMerkleTree(hashes);

// Get proof-of-inclusion for one leaf
const path = getMerklePath(tree, leafIndex);

// Verify without rebuilding the tree
const valid = verifyMerklePath(leafHash, root, path);

// Convenience: build + path in one call
const inclusion = getProofInclusion(hashes, targetHash);
// Returns: { valid, root, index, path } or null if not found
```

**Use case:** Notarize 10,000 records → publish ONE Merkle root → any single record can prove membership with a O(log n) path.

---

### Hash-chained audit log

```typescript
import { AuditChain, verifyAuditChain } from 'logos-notary';

const chain = new AuditChain();

chain.append('document_uploaded', 'PROOF-001', contentHash, { filename: 'contract.pdf' });
chain.append('document_signed',   'PROOF-001', contentHash, { signedBy: 'alice@acme.com' });
chain.append('document_shared',   'PROOF-001', contentHash, { sharedWith: 'bob@buyer.com' });

// Verify the entire chain
const result = chain.verify();
console.log(result.valid);   // true
console.log(result.entries); // 3

// Serialize → persist → restore → re-verify
const json = chain.toJSON();
const restored = AuditChain.fromJSON(json);
console.log(restored.verify().valid); // true

// Pass entries from your own database
const standaloneResult = verifyAuditChain(entriesFromDb);
```

Any modification to any entry invalidates all subsequent entries — provably, without a central server.

---

### Multi-signature

```typescript
import { createMultiSignatures, verifyMultiSignatures, buildDefaultSigners } from 'logos-notary';

// Build 3 signers derived from your master secret
const signers = buildDefaultSigners(masterSecret);

// Sign
const signatures = createMultiSignatures(contentHash, signers);

// Verify
const result = verifyMultiSignatures(contentHash, signatures, signers);
console.log(result.valid);  // true
console.log(result.passed); // 3
```

---

## Storage

`logos-notary` is **storage-agnostic**. It creates and verifies proofs; you decide where to persist them.

```typescript
// PostgreSQL example (Drizzle ORM)
await db.insert(proofs).values({
  proofId:       proof.proofId,
  contentHash:   proof.contentHash,
  signatureHash: proof.signatureHash,
  serverNonce:   proof.serverNonce,
  timestampedAt: proof.timestampedAt,
});

// Or just write to a file
import { writeFileSync } from 'fs';
writeFileSync(`proofs/${proof.proofId}.json`, JSON.stringify(proof));
```

---

## Security notes

- **Secret key**: Use at least 32 random characters. Store in environment variables, never in code.  
- **Signature algorithm**: SHA-256 HMAC with server nonce — resistant to length-extension attacks.  
- **Timing-safe comparison**: All signature comparisons use `crypto.timingSafeEqual` to prevent timing attacks.  
- **Nonce**: Every proof gets a fresh 16-byte random nonce — two identical documents produce different proofs.  
- **No content stored**: The proof only stores the hash — your actual content never leaves your system.

---

## Examples

Three complete, runnable examples are in [`/examples`](./examples):

| File | What it shows |
|---|---|
| `basic-proof.mjs` | Create, store, verify, and detect tampering on a document |
| `merkle-batch.mjs` | Batch 10 documents, prove individual inclusion, detect forgery |
| `audit-chain.mjs` | Build, serialize, restore, and tamper-test an audit chain |

```bash
# Build first
npm run build

# Then run any example
node examples/basic-proof.mjs
node examples/merkle-batch.mjs
node examples/audit-chain.mjs
```

---

## Tests

```bash
npm run build
node --test test/core.test.mjs
```

---

## Production proof

This library powers the [LOGOS Notary](https://logos257.com/verify) — a live public verification system with **924 cryptographic proofs** recorded in production as of March 2026.

Every prediction, token mint, and trade record in the LOGOS VPH-257 protocol is notarized using the exact algorithms in this library.

---

## Who uses cryptographic notarization

- **Fintech** — KYC/AML document integrity, loan application tamper-proofing
- **Legal tech** — Contract existence proof before dispute dates
- **Healthcare** — HIPAA-compliant audit trails for patient record changes
- **IP protection** — Timestamp creative work before publication
- **Supply chain** — Chain-of-custody provenance at each handoff
- **Compliance** — SOX, GDPR, ISO 27001 audit trail requirements

---

## License

MIT — [Grace AI Technologies LLC](https://logos257.com)

---

*"Timing is worth more than trust. Proof is worth more than both."*
