use crate::hashing::{hash_pair, Hash};

const ZERO_HASH: Hash = [0u8; 32];

/// A Merkle tree implementation for efficient commitment and verification.
///
/// The tree stores all levels in memory, which allows efficient root computation
/// but may use O(2n) memory for large trees.
#[derive(Clone, Debug)]
pub struct MerkleTree {
    levels: Vec<Vec<Hash>>,
}

impl MerkleTree {
    /// Create a Merkle tree from the given leaf hashes.
    ///
    /// Leaves are padded to the next power of two with zero hashes to ensure
    /// a deterministic layout. An empty leaf list will result in a tree with
    /// a single zero hash as the root.
    ///
    /// # Arguments
    /// * `leaves` - The leaf hashes to build the tree from
    pub fn from_leaves(mut leaves: Vec<Hash>) -> Self {
        let next_pow = leaves.len().next_power_of_two().max(1);
        leaves.resize(next_pow, ZERO_HASH);

        let mut levels = Vec::new();
        levels.push(leaves);

        while let Some(prev) = levels.last() {
            if prev.len() <= 1 {
                break;
            }
            let mut next = Vec::with_capacity((prev.len() + 1) >> 1);
            for pair in prev.chunks(2) {
                let left = pair[0];
                let right = *pair.get(1).unwrap_or(&ZERO_HASH);
                next.push(hash_pair(&left, &right));
            }
            levels.push(next);
        }

        Self { levels }
    }

    /// Returns the Merkle root hash.
    #[inline]
    #[must_use]
    pub fn root(&self) -> Hash {
        self.levels
            .last()
            .and_then(|level| level.first())
            .copied()
            .unwrap_or(ZERO_HASH)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_merkle_tree_single_leaf() {
        let leaf = [1u8; 32];
        let tree = MerkleTree::from_leaves(vec![leaf]);
        let root = tree.root();
        assert_ne!(root, ZERO_HASH);
    }

    #[test]
    fn test_merkle_tree_two_leaves() {
        let leaves = vec![[1u8; 32], [2u8; 32]];
        let tree = MerkleTree::from_leaves(leaves.clone());
        let root = tree.root();
        assert_ne!(root, ZERO_HASH);
        assert_ne!(root, leaves[0]);
        assert_ne!(root, leaves[1]);
    }

    #[test]
    fn test_merkle_tree_deterministic() {
        let leaves = vec![[1u8; 32], [2u8; 32], [3u8; 32], [4u8; 32]];
        let tree1 = MerkleTree::from_leaves(leaves.clone());
        let tree2 = MerkleTree::from_leaves(leaves);
        assert_eq!(tree1.root(), tree2.root());
    }

    #[test]
    fn test_merkle_tree_padding() {
        let leaves = vec![[1u8; 32]];
        let tree = MerkleTree::from_leaves(leaves);
        assert_eq!(tree.levels.len(), 1);
        assert_eq!(tree.levels[0].len(), 1);
    }

    #[test]
    fn test_merkle_tree_empty() {
        let tree = MerkleTree::from_leaves(vec![]);
        assert_eq!(tree.root(), ZERO_HASH);
    }
}
