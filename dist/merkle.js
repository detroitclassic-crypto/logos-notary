import crypto from 'crypto';
function pairHash(left, right) {
    return crypto.createHash('sha256').update(left + right).digest('hex');
}
export function buildMerkleTree(leaves) {
    if (leaves.length === 0) {
        return { root: '', leaves: [], tree: [] };
    }
    let currentLevel = [...leaves];
    const tree = [currentLevel];
    while (currentLevel.length > 1) {
        const nextLevel = [];
        for (let i = 0; i < currentLevel.length; i += 2) {
            const left = currentLevel[i];
            const right = currentLevel[i + 1] ?? left;
            nextLevel.push(pairHash(left, right));
        }
        currentLevel = nextLevel;
        tree.push(currentLevel);
    }
    return {
        root: currentLevel[0],
        leaves,
        tree,
    };
}
export function getMerklePath(tree, leafIndex) {
    const path = [];
    const positions = [];
    let currentIndex = leafIndex;
    for (let level = 0; level < tree.length - 1; level++) {
        const isRight = currentIndex % 2 === 1;
        const siblingIndex = isRight ? currentIndex - 1 : currentIndex + 1;
        if (siblingIndex < tree[level].length) {
            path.push(tree[level][siblingIndex]);
            positions.push(isRight ? 'left' : 'right');
        }
        currentIndex = Math.floor(currentIndex / 2);
    }
    return { path, positions };
}
export function verifyMerklePath(leafHash, merkleRoot, merklePath) {
    let current = leafHash;
    for (let i = 0; i < merklePath.path.length; i++) {
        const sibling = merklePath.path[i];
        const position = merklePath.positions[i];
        current = position === 'left' ? pairHash(sibling, current) : pairHash(current, sibling);
    }
    return current === merkleRoot;
}
export function getProofInclusion(leaves, leafHash) {
    const index = leaves.indexOf(leafHash);
    if (index === -1)
        return null;
    const { root, tree } = buildMerkleTree(leaves);
    const path = getMerklePath(tree, index);
    return {
        valid: true,
        root,
        index,
        path,
    };
}
export function verifyBatchInclusion(leafHash, merkleRoot, merklePath) {
    return verifyMerklePath(leafHash, merkleRoot, merklePath);
}
//# sourceMappingURL=merkle.js.map