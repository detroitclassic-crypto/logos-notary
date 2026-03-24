import crypto from 'crypto';
import type { MerkleTree, MerklePath, MerkleProof } from './types.js';

function pairHash(left: string, right: string): string {
  return crypto.createHash('sha256').update(left + right).digest('hex');
}

export function buildMerkleTree(leaves: string[]): MerkleTree {
  if (leaves.length === 0) {
    return { root: '', leaves: [], tree: [] };
  }

  let currentLevel = [...leaves];
  const tree: string[][] = [currentLevel];

  while (currentLevel.length > 1) {
    const nextLevel: string[] = [];

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

export function getMerklePath(tree: string[][], leafIndex: number): MerklePath {
  const path: string[] = [];
  const positions: ('left' | 'right')[] = [];

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

export function verifyMerklePath(
  leafHash: string,
  merkleRoot: string,
  merklePath: MerklePath
): boolean {
  let current = leafHash;

  for (let i = 0; i < merklePath.path.length; i++) {
    const sibling = merklePath.path[i];
    const position = merklePath.positions[i];
    current = position === 'left' ? pairHash(sibling, current) : pairHash(current, sibling);
  }

  return current === merkleRoot;
}

export function getProofInclusion(
  leaves: string[],
  leafHash: string
): MerkleProof | null {
  const index = leaves.indexOf(leafHash);
  if (index === -1) return null;

  const { root, tree } = buildMerkleTree(leaves);
  const path = getMerklePath(tree, index);

  return {
    valid: true,
    root,
    index,
    path,
  };
}

export function verifyBatchInclusion(
  leafHash: string,
  merkleRoot: string,
  merklePath: MerklePath
): boolean {
  return verifyMerklePath(leafHash, merkleRoot, merklePath);
}
