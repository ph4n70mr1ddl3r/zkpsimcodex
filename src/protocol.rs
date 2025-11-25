use k256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use rand::rngs::StdRng;

use crate::{
    account::Account,
    hashing::keccak256,
    merkle::{verify_proof, MerkleProof},
    zk::{prove_with_nullifier, verify_with_nullifier, NullifierProof},
};

#[derive(Clone, Debug)]
pub struct MembershipProof {
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
        &account.zk_scalar,
        &account.public_key_compressed(),
        merkle_root,
        &merkle_proof.leaf,
        external_nullifier,
        rng,
    );

    MembershipProof {
        merkle_proof,
        zk_proof,
    }
}

pub fn verify_membership_proof(
    merkle_root: &[u8; 32],
    external_nullifier: &[u8],
    proof: &MembershipProof,
) -> bool {
    // Ensure the supplied public key matches the committed Merkle leaf.
    if let Some(pub_point) =
        k256::ProjectivePoint::from_encoded_point(&proof.zk_proof.public_key).into_option()
    {
        let uncompressed = pub_point.to_affine().to_encoded_point(false);
        let pub_bytes = &uncompressed.as_bytes()[1..]; // strip 0x04 prefix
        let expected_leaf = keccak256(pub_bytes);
        if proof.merkle_proof.leaf != expected_leaf {
            return false;
        }
    } else {
        return false;
    }

    if !verify_proof(merkle_root, &proof.merkle_proof) {
        return false;
    }

    verify_with_nullifier(
        merkle_root,
        &proof.merkle_proof.leaf,
        external_nullifier,
        &proof.zk_proof,
    )
}
