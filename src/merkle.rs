use crate::hashing::{hash_pair, Hash};

#[derive(Clone, Debug)]
pub struct MerkleProof {
    pub leaf: Hash,
    pub path: Vec<(Hash, bool)>, // sibling hash, sibling_is_right
}

#[derive(Clone, Debug)]
pub struct MerkleTree {
    levels: Vec<Vec<Hash>>,
}

impl MerkleTree {
    pub fn from_leaves(mut leaves: Vec<Hash>) -> Self {
        // Pad to next power of two with zero hashes for deterministic layout.
        let next_pow = leaves.len().next_power_of_two().max(1);
        let zero = [0u8; 32];
        leaves.resize(next_pow, zero);

        let mut levels = Vec::new();
        levels.push(leaves);

        while levels.last().unwrap().len() > 1 {
            let prev = levels.last().unwrap();
            let mut next = Vec::with_capacity((prev.len() + 1) / 2);
            for pair in prev.chunks(2) {
                let left = pair[0];
                let right = *pair.get(1).unwrap_or(&zero);
                next.push(hash_pair(&left, &right));
            }
            levels.push(next);
        }

        Self { levels }
    }

    pub fn root(&self) -> Hash {
        self.levels.last().unwrap()[0]
    }

    pub fn proof(&self, index: usize) -> Option<MerkleProof> {
        if index >= self.levels.first().map(|lvl| lvl.len()).unwrap_or(0) {
            return None;
        }

        let mut idx = index;
        let mut path = Vec::new();

        for level in &self.levels[..self.levels.len() - 1] {
            let sibling_idx = if idx % 2 == 0 { idx + 1 } else { idx - 1 };
            let sibling_hash = *level.get(sibling_idx).unwrap_or(&[0u8; 32]);
            let sibling_is_right = idx % 2 == 0;
            path.push((sibling_hash, sibling_is_right));
            idx /= 2;
        }

        Some(MerkleProof {
            leaf: self.levels[0][index],
            path,
        })
    }
}

pub fn verify_proof(root: &Hash, proof: &MerkleProof) -> bool {
    let mut hash = proof.leaf;
    for (sibling, sibling_is_right) in &proof.path {
        hash = if *sibling_is_right {
            hash_pair(&hash, sibling)
        } else {
            hash_pair(sibling, &hash)
        };
    }
    &hash == root
}
