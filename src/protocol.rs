use crate::{
    account::Account,
    error::Result,
    zk::{ring_sign, ring_verify, RingSignature},
};
use rand::rngs::StdRng;

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
/// # Errors
/// Returns an error if the account's public key is not in the provided set,
/// or if signature creation fails.
pub fn create_membership_proof(
    account: &Account,
    public_keys: &[k256::EncodedPoint],
    message: &[u8],
    rng: &mut StdRng,
) -> Result<MembershipProof> {
    let signer_pk = account.public_key_compressed();
    let signer_index = public_keys
        .iter()
        .position(|pk| pk == &signer_pk)
        .ok_or(crate::error::ZkpError::SignerNotFound)?;

    let signature = account
        .with_zk_scalar(|scalar| ring_sign(message, public_keys, signer_index, scalar, rng))?;

    Ok(MembershipProof { signature })
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
) -> Result<bool> {
    ring_verify(message, public_keys, &proof.signature)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::account::generate_accounts;
    use rand::SeedableRng;

    #[test]
    fn test_create_and_verify_membership_proof() {
        let accounts = generate_accounts(10, 42);
        let prover = &accounts[3];
        let public_keys: Vec<_> = accounts
            .iter()
            .map(|acct| acct.public_key_compressed())
            .collect();

        let mut rng = StdRng::seed_from_u64(100);
        let message = b"membership test message";

        let proof = create_membership_proof(prover, &public_keys, message, &mut rng).unwrap();
        assert!(verify_membership_proof(&public_keys, message, &proof).unwrap());
    }

    #[test]
    fn test_verify_membership_proof_fails_wrong_message() {
        let accounts = generate_accounts(10, 42);
        let prover = &accounts[5];
        let public_keys: Vec<_> = accounts
            .iter()
            .map(|acct| acct.public_key_compressed())
            .collect();

        let mut rng = StdRng::seed_from_u64(200);
        let message = b"membership test message";

        let proof = create_membership_proof(prover, &public_keys, message, &mut rng).unwrap();
        assert!(!verify_membership_proof(&public_keys, b"wrong message", &proof).unwrap());
    }

    #[test]
    fn test_create_membership_proof_signer_not_found() {
        let accounts = generate_accounts(5, 42);
        let prover = &accounts[0];
        let other_accounts = generate_accounts(5, 99);
        let public_keys: Vec<_> = other_accounts
            .iter()
            .map(|acct| acct.public_key_compressed())
            .collect();

        let mut rng = StdRng::seed_from_u64(300);
        let message = b"membership test message";

        let result = create_membership_proof(prover, &public_keys, message, &mut rng);
        assert!(matches!(
            result,
            Err(crate::error::ZkpError::SignerNotFound)
        ));
    }
}
