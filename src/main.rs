mod account;
mod error;
mod hashing;
mod merkle;
mod protocol;
mod zk;

use account::{format_address, format_public_key, generate_accounts, Account};
use hashing::Hash;
use merkle::MerkleTree;
use protocol::{create_membership_proof, verify_membership_proof};
use rand::{rngs::StdRng, Rng, SeedableRng};

const DEFAULT_ACCOUNT_COUNT: usize = 100;
const DEFAULT_SEED: u64 = 2024;
const SEED_OFFSET: u64 = 99;

#[cfg(test)]
fn run_workflow(account_count: usize, seed: u64) -> Result<(), Box<dyn std::error::Error>> {
    let accounts = generate_accounts(account_count, seed);
    let leaves: Vec<Hash> = accounts.iter().map(|acct| acct.leaf).collect();
    let tree = MerkleTree::from_leaves(leaves);
    let merkle_root = tree.root();

    let mut rng = StdRng::seed_from_u64(seed + SEED_OFFSET);
    let target_index = rng.gen_range(0..account_count);
    let prover_acct = &accounts[target_index];

    let public_keys: Vec<_> = accounts
        .iter()
        .map(|acct| acct.public_key_compressed())
        .collect();

    let message = merkle_root.as_slice();
    let membership_proof = create_membership_proof(prover_acct, &public_keys, message, &mut rng)?;
    let verified = verify_membership_proof(&public_keys, message, &membership_proof)?;

    if !verified {
        return Err("Verification failed".into());
    }

    Ok(())
}

fn main() {
    let seed = DEFAULT_SEED;

    println!("Generating {DEFAULT_ACCOUNT_COUNT} dummy Ethereum-style accounts...");
    let accounts = generate_accounts(DEFAULT_ACCOUNT_COUNT, seed);
    let leaves: Vec<Hash> = accounts.iter().map(|acct| acct.leaf).collect();

    println!(
        "Building Merkle tree ({} leaves, padded to power of two)...",
        leaves.len()
    );
    let tree = MerkleTree::from_leaves(leaves);
    let merkle_root = tree.root();
    println!("Merkle root: 0x{}", hex::encode(merkle_root));

    let mut rng = StdRng::seed_from_u64(seed + SEED_OFFSET);
    let target_index = rng.gen_range(0..DEFAULT_ACCOUNT_COUNT);
    let prover_acct: &Account = &accounts[target_index];

    println!(
        "\nProver controls account #{target_index}: address {}, public key {}",
        format_address(&prover_acct.address),
        format_public_key(&prover_acct.public_key_compressed())
    );
    println!("Verifier never sees the private key.");

    let public_keys: Vec<_> = accounts
        .iter()
        .map(|acct| acct.public_key_compressed())
        .collect();

    // Bind the ring signature to the set by hashing the Merkle root into the message.
    let message = merkle_root.as_slice();
    let membership_proof = create_membership_proof(prover_acct, &public_keys, message, &mut rng)
        .expect("failed to create membership proof");

    println!(
        "\nRing signature produced over {} public keys.",
        public_keys.len()
    );

    let verified = verify_membership_proof(&public_keys, message, &membership_proof)
        .expect("verification failed");
    println!(
        "\nVerification result: {}",
        if verified {
            "ACCEPTED ✅"
        } else {
            "REJECTED ❌"
        }
    );

    println!("\nHow to scale:");
    println!("- Swap `account_count` to simulate larger rings; signature size grows linearly with the ring.");
    println!("- Bind the signature to additional context by hashing it into `message`.");
    println!("- For very large sets (millions), use a subset ring or a ZK circuit over the Merkle root to keep proofs small.");
}

#[cfg(test)]
mod integration_tests {
    use super::*;

    #[test]
    fn test_full_workflow_small_ring() {
        let result = run_workflow(5, 42);
        assert!(
            result.is_ok(),
            "Full workflow should succeed for small ring"
        );
    }

    #[test]
    fn test_full_workflow_medium_ring() {
        let result = run_workflow(50, 12345);
        assert!(
            result.is_ok(),
            "Full workflow should succeed for medium ring"
        );
    }

    #[test]
    fn test_full_workflow_power_of_two_ring() {
        let result = run_workflow(64, 999);
        assert!(
            result.is_ok(),
            "Full workflow should succeed for power of two ring"
        );
    }

    #[test]
    fn test_full_workflow_deterministic() {
        let result1 = run_workflow(10, 111);
        let result2 = run_workflow(10, 111);
        assert!(
            result1.is_ok() && result2.is_ok(),
            "Deterministic workflow should succeed"
        );
    }
}
