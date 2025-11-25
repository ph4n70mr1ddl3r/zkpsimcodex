use rand::rngs::StdRng;

use crate::{
    account::Account,
    zk::{ring_sign, ring_verify, RingSignature},
};

#[derive(Clone, Debug)]
pub struct MembershipProof {
    pub signature: RingSignature,
}

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

pub fn verify_membership_proof(
    public_keys: &[k256::EncodedPoint],
    message: &[u8],
    proof: &MembershipProof,
) -> bool {
    ring_verify(message, public_keys, &proof.signature)
}
