mod account;
mod hashing;
mod merkle;
mod protocol;
mod zk;

use account::{format_address, format_private_key, format_public_key, generate_accounts, Account};
use hashing::Hash;
use merkle::MerkleTree;
use protocol::{create_membership_proof, verify_membership_proof};
use rand::{rngs::StdRng, Rng, SeedableRng};

fn main() {
    // Configuration for the demo run.
    let account_count = 100;
    let seed = 2024u64;

    println!("Generating {account_count} dummy Ethereum-style accounts...");
    let accounts = generate_accounts(account_count, seed);
    let leaves: Vec<Hash> = accounts.iter().map(|acct| acct.leaf).collect();

    println!(
        "Building Merkle tree ({} leaves, padded to power of two)...",
        leaves.len()
    );
    let tree = MerkleTree::from_leaves(leaves);
    let merkle_root = tree.root();
    println!("Merkle root: 0x{}", hex::encode(merkle_root));

    // Select a prover at random to demonstrate anonymity from the verifier's perspective.
    let mut rng = StdRng::seed_from_u64(seed + 99);
    let target_index = rng.gen_range(0..account_count);
    let prover_acct: &Account = &accounts[target_index];

    println!(
        "\nProver controls account #{target_index}: address {}, public key {}",
        format_address(&prover_acct.address),
        format_public_key(&prover_acct.public_key_compressed())
    );
    println!(
        "Verifier never sees the private key: {}",
        format_private_key(&prover_acct.private_key_bytes())
    );

    let public_keys: Vec<_> = accounts
        .iter()
        .map(|acct| acct.public_key_compressed())
        .collect();

    // Bind the ring signature to the set by hashing the Merkle root into the message.
    let message = merkle_root.as_slice();
    let membership_proof = create_membership_proof(prover_acct, &public_keys, message, &mut rng);

    println!(
        "\nRing signature produced over {} public keys.",
        public_keys.len()
    );

    let verified = verify_membership_proof(&public_keys, message, &membership_proof);
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
