use sha2::{Digest, Sha256};
use tiny_keccak::{Hasher, Keccak};

pub type Hash = [u8; 32];

/// Hash arbitrary bytes into a 32-byte digest.
pub fn hash_bytes(input: impl AsRef<[u8]>) -> Hash {
    let mut hasher = Sha256::new();
    hasher.update(input);
    hasher.finalize().into()
}

/// Hash two concatenated hashes. Used for Merkle tree parents.
pub fn hash_pair(left: &Hash, right: &Hash) -> Hash {
    let mut buf = Vec::with_capacity(left.len() + right.len());
    buf.extend_from_slice(left);
    buf.extend_from_slice(right);
    hash_bytes(buf)
}

/// Compute Keccak-256 (used for Ethereum-style addresses and leaves).
pub fn keccak256(input: impl AsRef<[u8]>) -> Hash {
    let mut keccak = Keccak::v256();
    let mut output = [0u8; 32];
    keccak.update(input.as_ref());
    keccak.finalize(&mut output);
    output
}
