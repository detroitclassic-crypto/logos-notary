import type { MerkleTree, MerklePath, MerkleProof } from './types.js';
export declare function buildMerkleTree(leaves: string[]): MerkleTree;
export declare function getMerklePath(tree: string[][], leafIndex: number): MerklePath;
export declare function verifyMerklePath(leafHash: string, merkleRoot: string, merklePath: MerklePath): boolean;
export declare function getProofInclusion(leaves: string[], leafHash: string): MerkleProof | null;
export declare function verifyBatchInclusion(leafHash: string, merkleRoot: string, merklePath: MerklePath): boolean;
//# sourceMappingURL=merkle.d.ts.map