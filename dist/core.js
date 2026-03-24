import crypto from 'crypto';
export function hashContent(content) {
    if (Buffer.isBuffer(content)) {
        return crypto.createHash('sha256').update(content).digest('hex');
    }
    const data = typeof content === 'string' ? content : JSON.stringify(content);
    return crypto.createHash('sha256').update(data, 'utf8').digest('hex');
}
export function generateNonce() {
    return crypto.randomBytes(16).toString('hex');
}
export function generateProofId(prefix = 'PROOF', sequenceNumber) {
    const timestamp = Date.now().toString(36).toUpperCase();
    const random = crypto.randomBytes(3).toString('hex').toUpperCase();
    if (sequenceNumber !== undefined) {
        const seq = String(sequenceNumber).padStart(5, '0');
        return `${prefix}-${seq}-${timestamp.slice(-4)}${random.slice(-2)}`;
    }
    return `${prefix}-${timestamp}-${random}`;
}
export function signProof(contentHash, timestamp, nonce, secret) {
    const data = `${contentHash}|${timestamp.toISOString()}|${nonce}|${secret}`;
    return crypto.createHmac('sha256', secret).update(data).digest('hex');
}
export function verifySignature(contentHash, timestamp, nonce, signature, secret) {
    const expected = signProof(contentHash, timestamp, nonce, secret);
    try {
        return crypto.timingSafeEqual(Buffer.from(signature, 'hex'), Buffer.from(expected, 'hex'));
    }
    catch {
        return false;
    }
}
export function createProof(content, options, sequenceNumber) {
    const contentHash = hashContent(content);
    const timestampedAt = new Date();
    const serverNonce = generateNonce();
    const proofId = generateProofId(options.proofIdPrefix ?? 'PROOF', sequenceNumber);
    const signatureHash = signProof(contentHash, timestampedAt, serverNonce, options.secret);
    const verificationUrl = options.verificationBaseUrl
        ? `${options.verificationBaseUrl.replace(/\/$/, '')}/${proofId}`
        : undefined;
    const qrData = options.includeQr !== false
        ? JSON.stringify({
            proofId,
            hash: contentHash.substring(0, 16),
            ts: Math.floor(timestampedAt.getTime() / 1000),
            v: verificationUrl,
        })
        : undefined;
    return {
        proofId,
        contentHash,
        signatureHash,
        serverNonce,
        timestampedAt,
        algorithm: 'SHA256-HMAC',
        verificationUrl,
        qrData,
    };
}
export function verifyProof(proof, secret) {
    const valid = verifySignature(proof.contentHash, proof.timestampedAt, proof.serverNonce, proof.signatureHash, secret);
    return {
        valid,
        message: valid
            ? 'Proof is valid — content has not been tampered with'
            : 'Signature verification failed — content may have been altered',
        verifiedAt: new Date(),
        proof,
    };
}
export function verifyContentAgainstProof(content, proof, secret) {
    const contentHash = hashContent(content);
    if (contentHash !== proof.contentHash) {
        return {
            valid: false,
            message: 'Content hash mismatch — the content does not match the recorded proof',
            verifiedAt: new Date(),
            proof,
        };
    }
    return verifyProof(proof, secret);
}
//# sourceMappingURL=core.js.map