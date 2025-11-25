use rand::{rngs::StdRng, Rng};

use crate::hashing::{hash_bytes, Hash};

pub const PRIME: u128 = 18_446_744_073_709_551_557; // 2^64 - 59, a safe-to-handle 64-bit prime
pub const MODULUS: u64 = PRIME as u64;
pub const GROUP_ORDER: u64 = MODULUS - 1; // multiplicative group modulo PRIME
pub const GENERATOR: u64 = 5;

#[derive(Clone, Debug)]
pub struct NullifierProof {
    pub commitment_g: u64,
    pub commitment_h: u64,
    pub response: u64,
    pub challenge: u64,
    pub nullifier: u64,
}

pub fn mod_mul(a: u64, b: u64, modulus: u64) -> u64 {
    ((a as u128 * b as u128) % modulus as u128) as u64
}

pub fn mod_pow(mut base: u64, mut exp: u64, modulus: u64) -> u64 {
    let mut result: u64 = 1;
    base %= modulus;
    while exp > 0 {
        if exp & 1 == 1 {
            result = mod_mul(result, base, modulus);
        }
        base = mod_mul(base, base, modulus);
        exp >>= 1;
    }
    result
}

/// Map 32 random bytes into a non-zero scalar in the field.
pub fn group_scalar_from_bytes(bytes: &[u8; 32]) -> u64 {
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&bytes[..8]);
    let raw = u64::from_be_bytes(buf);
    1 + (raw % (GROUP_ORDER - 1))
}

pub fn derive_public_key(secret: u64) -> u64 {
    mod_pow(GENERATOR, secret, MODULUS)
}

pub fn hash_to_scalar(data: impl AsRef<[u8]>) -> u64 {
    let digest = hash_bytes(data);
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&digest[..8]);
    let raw = u64::from_be_bytes(buf);
    1 + (raw % (GROUP_ORDER - 1))
}

fn derive_nullifier_base(public_key: u64, merkle_root: &Hash, leaf: &Hash, context: &[u8]) -> u64 {
    let mut transcript = Vec::new();
    transcript.extend_from_slice(&public_key.to_be_bytes());
    transcript.extend_from_slice(merkle_root);
    transcript.extend_from_slice(leaf);
    transcript.extend_from_slice(context);
    hash_to_scalar(transcript)
}

fn compute_challenge(
    commitment_g: u64,
    commitment_h: u64,
    public_key: u64,
    nullifier: u64,
    merkle_root: &Hash,
    leaf: &Hash,
    context: &[u8],
) -> u64 {
    let mut transcript = Vec::new();
    transcript.extend_from_slice(&commitment_g.to_be_bytes());
    transcript.extend_from_slice(&commitment_h.to_be_bytes());
    transcript.extend_from_slice(&public_key.to_be_bytes());
    transcript.extend_from_slice(&nullifier.to_be_bytes());
    transcript.extend_from_slice(merkle_root);
    transcript.extend_from_slice(leaf);
    transcript.extend_from_slice(context);
    hash_to_scalar(transcript)
}

/// Generate a Schnorr-style proof of knowledge of `secret` that also ties in a deterministic
/// nullifier derived from the same secret and the provided context.
pub fn prove_with_nullifier(
    secret: u64,
    public_key: u64,
    merkle_root: &Hash,
    leaf: &Hash,
    context: &[u8],
    rng: &mut StdRng,
) -> NullifierProof {
    let nullifier_base = derive_nullifier_base(public_key, merkle_root, leaf, context);
    let random_scalar = rng.gen_range(1..GROUP_ORDER - 1);

    let commitment_g = mod_pow(GENERATOR, random_scalar, MODULUS);
    let commitment_h = mod_pow(nullifier_base, random_scalar, MODULUS);
    let nullifier = mod_pow(nullifier_base, secret, MODULUS);

    let challenge = compute_challenge(
        commitment_g,
        commitment_h,
        public_key,
        nullifier,
        merkle_root,
        leaf,
        context,
    );

    let response = (random_scalar as u128
        + (challenge as u128 * secret as u128) % GROUP_ORDER as u128)
        % GROUP_ORDER as u128;

    NullifierProof {
        commitment_g,
        commitment_h,
        response: response as u64,
        challenge,
        nullifier,
    }
}

pub fn verify_with_nullifier(
    public_key: u64,
    merkle_root: &Hash,
    leaf: &Hash,
    context: &[u8],
    proof: &NullifierProof,
) -> bool {
    let nullifier_base = derive_nullifier_base(public_key, merkle_root, leaf, context);
    let expected_challenge = compute_challenge(
        proof.commitment_g,
        proof.commitment_h,
        public_key,
        proof.nullifier,
        merkle_root,
        leaf,
        context,
    );

    if expected_challenge != proof.challenge {
        return false;
    }

    let lhs_g = mod_pow(GENERATOR, proof.response, MODULUS);
    let rhs_g = mod_mul(
        proof.commitment_g,
        mod_pow(public_key, proof.challenge, MODULUS),
        MODULUS,
    );

    let lhs_h = mod_pow(nullifier_base, proof.response, MODULUS);
    let rhs_h = mod_mul(
        proof.commitment_h,
        mod_pow(proof.nullifier, proof.challenge, MODULUS),
        MODULUS,
    );

    lhs_g == rhs_g && lhs_h == rhs_h
}
