use k256::{
    elliptic_curve::bigint::U256,
    elliptic_curve::ff::Field,
    elliptic_curve::ops::Reduce,
    elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint},
    EncodedPoint, FieldBytes, ProjectivePoint, Scalar,
};
use rand::rngs::StdRng;
use sha2::{Digest, Sha256};

use crate::hashing::Hash;

#[derive(Clone, Debug)]
pub struct NullifierProof {
    pub commitment_g: EncodedPoint,
    pub commitment_h: EncodedPoint,
    pub response: Scalar,
    pub challenge: Scalar,
    pub nullifier: EncodedPoint,
    pub public_key: EncodedPoint,
}

fn hash_to_scalar(data: impl AsRef<[u8]>) -> Scalar {
    let digest = Sha256::digest(data);
    <Scalar as Reduce<U256>>::reduce_bytes(&FieldBytes::from(digest))
}

fn derive_nullifier_base(
    public_key: &EncodedPoint,
    merkle_root: &Hash,
    leaf: &Hash,
    context: &[u8],
) -> ProjectivePoint {
    let mut transcript = Vec::new();
    transcript.extend_from_slice(public_key.as_bytes());
    transcript.extend_from_slice(merkle_root);
    transcript.extend_from_slice(leaf);
    transcript.extend_from_slice(context);
    let scalar = hash_to_scalar(transcript) + Scalar::ONE; // avoid zero
    ProjectivePoint::GENERATOR * scalar
}

fn compute_challenge(
    commitment_g: &EncodedPoint,
    commitment_h: &EncodedPoint,
    public_key: &EncodedPoint,
    nullifier: &EncodedPoint,
    merkle_root: &Hash,
    leaf: &Hash,
    context: &[u8],
) -> Scalar {
    let mut transcript = Vec::new();
    transcript.extend_from_slice(commitment_g.as_bytes());
    transcript.extend_from_slice(commitment_h.as_bytes());
    transcript.extend_from_slice(public_key.as_bytes());
    transcript.extend_from_slice(nullifier.as_bytes());
    transcript.extend_from_slice(merkle_root);
    transcript.extend_from_slice(leaf);
    transcript.extend_from_slice(context);
    hash_to_scalar(transcript)
}

/// Generate a Schnorr-style proof of knowledge of `secret` on secp256k1 that also ties in a
/// deterministic nullifier derived from the same secret and the provided context.
pub fn prove_with_nullifier(
    secret: &Scalar,
    public_key: &EncodedPoint,
    merkle_root: &Hash,
    leaf: &Hash,
    context: &[u8],
    rng: &mut StdRng,
) -> NullifierProof {
    let nullifier_base = derive_nullifier_base(public_key, merkle_root, leaf, context);
    let random_scalar = Scalar::random(rng);

    let commitment_g = (ProjectivePoint::GENERATOR * random_scalar).to_affine();
    let commitment_h = (nullifier_base * random_scalar).to_affine();
    let nullifier_point = (nullifier_base * secret).to_affine();

    let challenge = compute_challenge(
        &commitment_g.to_encoded_point(true),
        &commitment_h.to_encoded_point(true),
        public_key,
        &nullifier_point.to_encoded_point(true),
        merkle_root,
        leaf,
        context,
    );

    let response = random_scalar + (challenge * secret);

    NullifierProof {
        commitment_g: commitment_g.to_encoded_point(true),
        commitment_h: commitment_h.to_encoded_point(true),
        response,
        challenge,
        nullifier: nullifier_point.to_encoded_point(true),
        public_key: public_key.clone(),
    }
}

pub fn verify_with_nullifier(
    merkle_root: &Hash,
    leaf: &Hash,
    context: &[u8],
    proof: &NullifierProof,
) -> bool {
    let public_point = match ProjectivePoint::from_encoded_point(&proof.public_key).into_option() {
        Some(p) => p,
        None => return false,
    };
    let commitment_g = match ProjectivePoint::from_encoded_point(&proof.commitment_g).into_option()
    {
        Some(p) => p,
        None => return false,
    };
    let commitment_h = match ProjectivePoint::from_encoded_point(&proof.commitment_h).into_option()
    {
        Some(p) => p,
        None => return false,
    };
    let nullifier_point = match ProjectivePoint::from_encoded_point(&proof.nullifier).into_option()
    {
        Some(p) => p,
        None => return false,
    };

    let nullifier_base = derive_nullifier_base(&proof.public_key, merkle_root, leaf, context);
    let expected_challenge = compute_challenge(
        &proof.commitment_g,
        &proof.commitment_h,
        &proof.public_key,
        &proof.nullifier,
        merkle_root,
        leaf,
        context,
    );

    if expected_challenge != proof.challenge {
        return false;
    }

    let lhs_g: ProjectivePoint = (ProjectivePoint::GENERATOR * proof.response)
        .to_affine()
        .into();
    let rhs_g: ProjectivePoint = (commitment_g + (public_point * proof.challenge))
        .to_affine()
        .into();

    let lhs_h: ProjectivePoint = (nullifier_base * proof.response).to_affine().into();
    let rhs_h: ProjectivePoint = (commitment_h + (nullifier_point * proof.challenge))
        .to_affine()
        .into();

    lhs_g == rhs_g && lhs_h == rhs_h
}
