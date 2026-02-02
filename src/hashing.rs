use sha2::{Digest, Sha256};
use tiny_keccak::{Hasher, Keccak};

pub type Hash = [u8; 32];

const HASH_SIZE: usize = 32;

/// Hash arbitrary bytes into a 32-byte digest using SHA-256.
///
/// # Examples
/// ```
/// use zkpsimcodex::hashing::hash_bytes;
/// let hash = hash_bytes(b"hello world");
/// assert_eq!(hash.len(), 32);
/// ```
#[allow(dead_code)]
#[must_use]
pub fn hash_bytes(input: impl AsRef<[u8]>) -> Hash {
    let mut hasher = Sha256::new();
    hasher.update(input);
    hasher.finalize().into()
}

/// Hash two concatenated hashes. Used for Merkle tree parents.
///
/// Concatenates the two 32-byte hashes and hashes the result.
///
/// # Examples
/// ```
/// use zkpsimcodex::hashing::hash_pair;
/// let left = [1u8; 32];
/// let right = [2u8; 32];
/// let hash = hash_pair(&left, &right);
/// assert_eq!(hash.len(), 32);
/// ```
#[inline]
#[must_use]
pub fn hash_pair(left: &Hash, right: &Hash) -> Hash {
    let mut hasher = Sha256::new();
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().into()
}

/// Compute Keccak-256 (used for Ethereum-style addresses and leaves).
///
/// Returns the 32-byte Keccak-256 hash of the input.
///
/// # Examples
/// ```
/// use zkpsimcodex::hashing::keccak256;
/// let hash = keccak256(b"hello world");
/// assert_eq!(hash.len(), 32);
/// ```
#[must_use]
pub fn keccak256(input: impl AsRef<[u8]>) -> Hash {
    let mut keccak = Keccak::v256();
    let mut output = [0u8; HASH_SIZE];
    keccak.update(input.as_ref());
    keccak.finalize(&mut output);
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_bytes_deterministic() {
        let data = b"test data";
        let hash1 = hash_bytes(data);
        let hash2 = hash_bytes(data);
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_hash_bytes_different() {
        let hash1 = hash_bytes(b"data1");
        let hash2 = hash_bytes(b"data2");
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_hash_pair_deterministic() {
        let left = [1u8; 32];
        let right = [2u8; 32];
        let hash1 = hash_pair(&left, &right);
        let hash2 = hash_pair(&left, &right);
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_hash_pair_order_matters() {
        let left = [1u8; 32];
        let right = [2u8; 32];
        let hash1 = hash_pair(&left, &right);
        let hash2 = hash_pair(&right, &left);
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_keccak256_deterministic() {
        let data = b"test data";
        let hash1 = keccak256(data);
        let hash2 = keccak256(data);
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_keccak256_different_from_sha256() {
        let data = b"test data";
        let sha_hash = hash_bytes(data);
        let keccak_hash = keccak256(data);
        assert_ne!(sha_hash, keccak_hash);
    }

    #[test]
    fn test_hash_size() {
        let hash = hash_bytes(b"test");
        assert_eq!(hash.len(), HASH_SIZE);
        let keccak = keccak256(b"test");
        assert_eq!(keccak.len(), HASH_SIZE);
    }
}
