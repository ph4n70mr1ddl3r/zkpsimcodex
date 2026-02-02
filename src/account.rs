use k256::{elliptic_curve::sec1::ToEncodedPoint, EncodedPoint, PublicKey, Scalar, SecretKey};
use rand::{rngs::StdRng, SeedableRng};

use crate::hashing::{keccak256, Hash};

const ADDRESS_SIZE: usize = 20;
const ADDRESS_OFFSET: usize = 12;

/// Ethereum-style account: secp256k1 keypair and address derived via Keccak-256.
///
/// Contains the secret and public keys, Ethereum address, and the Merkle tree leaf
/// which is the Keccak-256 hash of the uncompressed public key.
#[derive(Clone, Debug)]
pub struct Account {
    pub public_key: PublicKey,
    pub address: [u8; 20],
    pub leaf: Hash,
    zk_scalar: Scalar,
}

impl Account {
    /// Generate a random Ethereum-style account.
    ///
    /// # Arguments
    /// * `rng` - Random number generator
    pub fn random(rng: &mut StdRng) -> Self {
        let secret_key = SecretKey::random(rng);
        let public_key: PublicKey = secret_key.public_key();

        let uncompressed = public_key.to_encoded_point(false);
        let pubkey_body = &uncompressed.as_bytes()[1..];

        let address_hash = keccak256(pubkey_body);
        let mut address = [0u8; ADDRESS_SIZE];
        address.copy_from_slice(&address_hash[ADDRESS_OFFSET..]);

        let zk_scalar = *secret_key.to_nonzero_scalar();

        Self {
            public_key,
            address,
            leaf: address_hash,
            zk_scalar,
        }
    }

    /// Returns the compressed SEC1-encoded public key.
    pub fn public_key_compressed(&self) -> EncodedPoint {
        self.public_key.to_encoded_point(true)
    }

    /// Provides controlled access to the ZK scalar for signing operations.
    ///
    /// This method allows the caller to use the private scalar in a controlled
    /// manner without directly exposing it, enhancing security.
    pub fn with_zk_scalar<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&Scalar) -> R,
    {
        f(&self.zk_scalar)
    }
}

/// Deterministically generate a reproducible list of accounts.
///
/// # Arguments
/// * `count` - Number of accounts to generate
/// * `seed` - Seed for the random number generator
///
/// # Returns
/// A vector of accounts, each generated with a deterministic sequence.
pub fn generate_accounts(count: usize, seed: u64) -> Vec<Account> {
    let mut rng = StdRng::seed_from_u64(seed);
    let mut accounts = Vec::with_capacity(count);
    for _ in 0..count {
        accounts.push(Account::random(&mut rng));
    }
    accounts
}

/// Format an Ethereum address for human-readable output.
pub fn format_address(addr: &[u8; ADDRESS_SIZE]) -> String {
    format!("0x{}", hex::encode(addr))
}

/// Format a public key for human-readable output.
pub fn format_public_key(pk: &EncodedPoint) -> String {
    format!("0x{}", hex::encode(pk.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_account_generation_deterministic() {
        let mut rng1 = StdRng::seed_from_u64(42);
        let mut rng2 = StdRng::seed_from_u64(42);

        let acct1 = Account::random(&mut rng1);
        let acct2 = Account::random(&mut rng2);

        assert_eq!(acct1.address, acct2.address);
        assert_eq!(acct1.leaf, acct2.leaf);
        assert_eq!(acct1.with_zk_scalar(|s| *s), acct2.with_zk_scalar(|s| *s));
    }

    #[test]
    fn test_account_generation_different() {
        let mut rng = StdRng::seed_from_u64(42);

        let acct1 = Account::random(&mut rng);
        let acct2 = Account::random(&mut rng);

        assert_ne!(acct1.address, acct2.address);
        assert_ne!(acct1.leaf, acct2.leaf);
        assert_ne!(acct1.with_zk_scalar(|s| *s), acct2.with_zk_scalar(|s| *s));
    }

    #[test]
    fn test_generate_accounts_count() {
        let accounts = generate_accounts(10, 42);
        assert_eq!(accounts.len(), 10);
    }

    #[test]
    fn test_generate_accounts_deterministic() {
        let accounts1 = generate_accounts(5, 42);
        let accounts2 = generate_accounts(5, 42);

        assert_eq!(accounts1.len(), accounts2.len());
        for (a1, a2) in accounts1.iter().zip(accounts2.iter()) {
            assert_eq!(a1.address, a2.address);
            assert_eq!(a1.leaf, a2.leaf);
        }
    }

    #[test]
    fn test_format_address() {
        let addr = [
            1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20,
        ];
        let formatted = format_address(&addr);
        assert!(formatted.starts_with("0x"));
        assert_eq!(formatted.len(), 42);
    }

    #[test]
    fn test_public_key_compressed() {
        let mut rng = StdRng::seed_from_u64(42);
        let account = Account::random(&mut rng);
        let compressed = account.public_key_compressed();
        let bytes = compressed.as_bytes();
        let prefix = bytes[0];
        assert!(
            prefix == 0x02 || prefix == 0x03,
            "Compressed key prefix must be 0x02 or 0x03"
        );
        assert_eq!(
            bytes.len(),
            33,
            "Compressed SEC1 encoding should be 33 bytes"
        );
    }
}
