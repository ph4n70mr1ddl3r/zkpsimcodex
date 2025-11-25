use sha2::{Digest, Sha256};

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

/// Hash a u64 value in big-endian form.
pub fn hash_u64(value: u64) -> Hash {
    hash_bytes(value.to_be_bytes())
}

/// Convenience for logging: shorten a hash to a readable prefix.
pub fn short_hash_tag(hash: &Hash) -> String {
    let encoded = hex::encode(hash);
    encoded[..8].to_string()
}
