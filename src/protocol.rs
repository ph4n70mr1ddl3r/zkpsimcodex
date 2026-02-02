use rand::rngs::StdRng;

use crate::{
    account::Account,
    zk::{ring_sign, ring_verify, RingSignature},
};

/// A proof of membership in a set, using a ring signature.
///
/// The prover can demonstrate they own one of the accounts in the set
/// without revealing which one.
#[derive(Clone, Debug)]
pub struct MembershipProof {
    pub signature: RingSignature,
}

/// Create a membership proof for an account.
///
/// Creates a ring signature proving the account owns one of the keys in the set
/// without revealing which one.
///
/// # Arguments
/// * `account` - The account creating the proof
/// * `public_keys` - The set of public keys
/// * `message` - The message to bind the signature to
/// * `rng` - Random number generator
///
/// # Panics
/// Panics if the account's public key is not in the provided set.
pub fn create_membership_proof(
    account: &Account,
    public_keys: &[k256::EncodedPoint],
    message: &[u8],
    rng: &mut StdRng,
) -> MembershipProof {
    let signer_pk = account.public_key_compressed();
    let signer_index = public_keys
        .iter()
        .position(|pk| pk == &signer_pk)
        .expect("signer public key must be in the provided set");

    let signature = ring_sign(message, public_keys, signer_index, &account.zk_scalar, rng);

    MembershipProof { signature }
}

/// Verify a membership proof.
///
/// Returns true if the proof is valid for the given message and public keys.
///
/// # Arguments
/// * `public_keys` - The set of public keys
/// * `message` - The message the proof was bound to
/// * `proof` - The membership proof to verify
#[must_use]
pub fn verify_membership_proof(
    public_keys: &[k256::EncodedPoint],
    message: &[u8],
    proof: &MembershipProof,
) -> bool {
    ring_verify(message, public_keys, &proof.signature)
}
