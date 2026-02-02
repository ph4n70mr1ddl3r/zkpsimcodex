use k256::{elliptic_curve::sec1::ToEncodedPoint, EncodedPoint, PublicKey, Scalar, SecretKey};
use rand::{rngs::StdRng, SeedableRng};

use crate::hashing::{keccak256, Hash};

/// Ethereum-style account: secp256k1 keypair and address derived via Keccak-256.
///
/// Contains the secret and public keys, Ethereum address, and the Merkle tree leaf
/// which is the Keccak-256 hash of the uncompressed public key.
#[derive(Clone, Debug)]
pub struct Account {
    pub public_key: PublicKey,
    pub address: [u8; 20],
    pub leaf: Hash,
    pub zk_scalar: Scalar,
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
        let pubkey_body = uncompressed.as_bytes()[1..].to_vec();

        let address_hash = keccak256(&pubkey_body);
        let mut address = [0u8; 20];
        address.copy_from_slice(&address_hash[12..]);

        let leaf = keccak256(&pubkey_body);
        let zk_scalar = *secret_key.to_nonzero_scalar();

        Self {
            public_key,
            address,
            leaf,
            zk_scalar,
        }
    }

    /// Returns the compressed SEC1-encoded public key.
    pub fn public_key_compressed(&self) -> EncodedPoint {
        self.public_key.to_encoded_point(true)
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
    (0..count).map(|_| Account::random(&mut rng)).collect()
}

/// Format helpers for human-readable output.
pub fn format_address(addr: &[u8; 20]) -> String {
    format!("0x{}", hex::encode(addr))
}

pub fn format_public_key(pk: &EncodedPoint) -> String {
    format!("0x{}", hex::encode(pk.as_bytes()))
}
