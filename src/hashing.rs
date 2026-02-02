use sha2::{Digest, Sha256};
use tiny_keccak::{Hasher, Keccak};

pub type Hash = [u8; 32];

const HASH_SIZE: usize = 32;

/// Hash arbitrary bytes into a 32-byte digest using SHA-256.
pub fn hash_bytes(input: impl AsRef<[u8]>) -> Hash {
    let mut hasher = Sha256::new();
    hasher.update(input);
    hasher.finalize().into()
}

/// Hash two concatenated hashes. Used for Merkle tree parents.
///
/// Concatenates the two 32-byte hashes and hashes the result.
pub fn hash_pair(left: &Hash, right: &Hash) -> Hash {
    let mut buf = [0u8; HASH_SIZE * 2];
    buf[..HASH_SIZE].copy_from_slice(left);
    buf[HASH_SIZE..].copy_from_slice(right);
    hash_bytes(buf)
}

/// Compute Keccak-256 (used for Ethereum-style addresses and leaves).
///
/// Returns the 32-byte Keccak-256 hash of the input.
pub fn keccak256(input: impl AsRef<[u8]>) -> Hash {
    let mut keccak = Keccak::v256();
    let mut output = [0u8; HASH_SIZE];
    keccak.update(input.as_ref());
    keccak.finalize(&mut output);
    output
}
