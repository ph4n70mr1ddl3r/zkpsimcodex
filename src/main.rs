mod account;
mod hashing;
mod merkle;
mod protocol;
mod zk;

use account::{format_address, format_private_key, format_public_key, generate_accounts, Account};
use hashing::{short_hash_tag, Hash};
use merkle::MerkleTree;
use protocol::{create_membership_proof, verify_membership_proof};
use rand::{rngs::StdRng, Rng, SeedableRng};

fn main() {
    // Configuration for the demo run.
    let account_count = 100;
    let seed = 2024u64;
    let external_nullifier = b"epoch-1-nullifier";

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

    let merkle_proof = tree
        .proof(target_index)
        .expect("proof generation should succeed for valid index");

    let membership_proof = create_membership_proof(
        prover_acct,
        merkle_proof,
        &merkle_root,
        external_nullifier,
        &mut rng,
    );

    let nullifier_hex = hex::encode(membership_proof.zk_proof.nullifier.as_bytes());
    println!("\nDeterministic nullifier (ties to account + context): 0x{nullifier_hex}");
    println!(
        "Merkle path length: {} (example hash tag: {})",
        membership_proof.merkle_proof.path.len(),
        short_hash_tag(&membership_proof.merkle_proof.leaf)
    );

    let verified = verify_membership_proof(&merkle_root, external_nullifier, &membership_proof);
    println!(
        "\nVerification result: {}",
        if verified {
            "ACCEPTED ✅"
        } else {
            "REJECTED ❌"
        }
    );

    println!("\nHow to scale:");
    println!("- Swap `account_count` to simulate larger sets; the Merkle tree keeps verifier data small.");
    println!("- `external_nullifier` can be rotated per epoch to prevent double-use with the deterministic tag.");
    println!("- The Schnorr-with-nullifier proof stays constant-size regardless of set size.");
}
