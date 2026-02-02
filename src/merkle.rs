use crate::hashing::{hash_pair, Hash};

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
    /// a deterministic layout.
    ///
    /// # Arguments
    /// * `leaves` - The leaf hashes to build the tree from
    pub fn from_leaves(mut leaves: Vec<Hash>) -> Self {
        // Pad to next power of two with zero hashes for deterministic layout.
        let next_pow = leaves.len().next_power_of_two().max(1);
        let zero = [0u8; 32];
        leaves.resize(next_pow, zero);

        let mut levels = Vec::new();
        levels.push(leaves);

        while levels.last().unwrap().len() > 1 {
            let prev = levels.last().unwrap();
            let mut next = Vec::with_capacity((prev.len() + 1) >> 1);
            for pair in prev.chunks(2) {
                let left = pair[0];
                let right = *pair.get(1).unwrap_or(&zero);
                next.push(hash_pair(&left, &right));
            }
            levels.push(next);
        }

        Self { levels }
    }

    /// Returns the Merkle root hash.
    #[must_use]
    pub fn root(&self) -> Hash {
        self.levels.last().unwrap()[0]
    }
}
