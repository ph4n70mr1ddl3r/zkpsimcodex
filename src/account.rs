use k256::{elliptic_curve::sec1::ToEncodedPoint, EncodedPoint, PublicKey, Scalar, SecretKey};
use rand::{rngs::StdRng, SeedableRng};

use crate::hashing::{keccak256, Hash};

/// Ethereum-style account: secp256k1 keypair and address derived via Keccak-256.
#[derive(Clone, Debug)]
pub struct Account {
    pub secret_key: SecretKey,
    pub public_key: PublicKey,
    pub address: [u8; 20],
    pub leaf: Hash, // Keccak-256 of the uncompressed public key (Ethereum-style commitment)
    pub zk_scalar: Scalar, // Same secret as the ECDSA key, reused for the Schnorr proof
}

impl Account {
    pub fn random(rng: &mut StdRng) -> Self {
        let secret_key = SecretKey::random(rng);
        let public_key: PublicKey = secret_key.public_key();

        let uncompressed = public_key.to_encoded_point(false);
        let pubkey_body = uncompressed.as_bytes()[1..].to_vec(); // drop 0x04 prefix

        let address_hash = keccak256(&pubkey_body);
        let mut address = [0u8; 20];
        address.copy_from_slice(&address_hash[12..]);

        let leaf = keccak256(&pubkey_body);
        let zk_scalar = *secret_key.to_nonzero_scalar();

        Self {
            secret_key,
            public_key,
            address,
            leaf,
            zk_scalar,
        }
    }

    pub fn public_key_compressed(&self) -> EncodedPoint {
        self.public_key.to_encoded_point(true)
    }

    pub fn private_key_bytes(&self) -> [u8; 32] {
        self.secret_key.to_bytes().into()
    }
}

/// Deterministically generate a reproducible list of accounts (useful for tests).
pub fn generate_accounts(count: usize, seed: u64) -> Vec<Account> {
    let mut rng = StdRng::seed_from_u64(seed);
    (0..count).map(|_| Account::random(&mut rng)).collect()
}

/// Format helpers for human-readable output.
pub fn format_address(addr: &[u8; 20]) -> String {
    format!("0x{}", hex::encode(addr))
}

pub fn format_private_key(priv_key: &[u8; 32]) -> String {
    format!("0x{}", hex::encode(priv_key))
}

pub fn format_public_key(pk: &EncodedPoint) -> String {
    format!("0x{}", hex::encode(pk.as_bytes()))
}
