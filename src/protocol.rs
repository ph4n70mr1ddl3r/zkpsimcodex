use rand::rngs::StdRng;

use crate::{
    account::Account,
    hashing::hash_u64,
    merkle::{verify_proof, MerkleProof},
    zk::{prove_with_nullifier, verify_with_nullifier, NullifierProof},
};

#[derive(Clone, Debug)]
pub struct MembershipProof {
    pub public_key: u64,
    pub merkle_proof: MerkleProof,
    pub zk_proof: NullifierProof,
}

pub fn create_membership_proof(
    account: &Account,
    merkle_proof: MerkleProof,
    merkle_root: &[u8; 32],
    external_nullifier: &[u8],
    rng: &mut StdRng,
) -> MembershipProof {
    let zk_proof = prove_with_nullifier(
        account.secret_scalar,
        account.public_key,
        merkle_root,
        &merkle_proof.leaf,
        external_nullifier,
        rng,
    );

    MembershipProof {
        public_key: account.public_key,
        merkle_proof,
        zk_proof,
    }
}

pub fn verify_membership_proof(
    merkle_root: &[u8; 32],
    external_nullifier: &[u8],
    proof: &MembershipProof,
) -> bool {
    let expected_leaf = hash_u64(proof.public_key);
    if proof.merkle_proof.leaf != expected_leaf {
        return false;
    }

    if !verify_proof(merkle_root, &proof.merkle_proof) {
        return false;
    }

    verify_with_nullifier(
        proof.public_key,
        merkle_root,
        &proof.merkle_proof.leaf,
        external_nullifier,
        &proof.zk_proof,
    )
}
