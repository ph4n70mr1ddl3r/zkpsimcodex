use rand::{rngs::StdRng, Rng, SeedableRng};

use crate::{
    hashing::{hash_bytes, hash_u64, Hash},
    zk::{derive_public_key, group_scalar_from_bytes},
};

/// Simplified Ethereum-like account used only for demonstration.
/// Private keys are random 32-byte arrays; public keys are small group elements
/// derived from the private scalar; addresses are the first 20 bytes of a hash.
#[derive(Clone, Debug)]
pub struct Account {
    pub private_key: [u8; 32],
    pub public_key: u64,
    pub address: [u8; 20],
    pub leaf: Hash,
    pub secret_scalar: u64,
}

impl Account {
    pub fn random(rng: &mut StdRng) -> Self {
        let mut private_key = [0u8; 32];
        rng.fill(&mut private_key);

        let secret_scalar = group_scalar_from_bytes(&private_key);
        let public_key = derive_public_key(secret_scalar);

        let mut address_input = Vec::with_capacity(8 + private_key.len());
        address_input.extend_from_slice(&public_key.to_be_bytes());
        address_input.extend_from_slice(&private_key);
        let address_full = hash_bytes(address_input);
        let mut address = [0u8; 20];
        address.copy_from_slice(&address_full[..20]);

        // Leaf commits to the public key only; the private key remains hidden.
        let leaf = hash_u64(public_key);

        Self {
            private_key,
            public_key,
            address,
            leaf,
            secret_scalar,
        }
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

pub fn format_public_key(pk: u64) -> String {
    format!("0x{:016x}", pk)
}
